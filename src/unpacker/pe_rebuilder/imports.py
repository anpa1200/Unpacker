"""Strict, bounded PE32 import-table validation for retained input data."""
import re,struct


def file_backed_data(pe,rva,size,sections):
    if type(rva) is not int or type(size) is not int or rva<0 or size<0:raise ValueError('Invalid RVA range')
    matches=[s for s in sections if s.VirtualAddress<=rva and rva+size<=s.VirtualAddress+min(s.Misc_VirtualSize or s.SizeOfRawData,s.SizeOfRawData)]
    if len(matches)!=1:raise ValueError('RVA is not uniquely file-backed in retained sections')
    data=pe.get_data(rva,size)
    if len(data)!=size:raise ValueError('Truncated retained section')
    return data


def c_string(pe,rva,sections,limit):
    result=bytearray()
    for offset in range(limit):
        value=file_backed_data(pe,rva+offset,1,sections)[0]
        if value==0:
            if not result:raise ValueError('Empty import name')
            return bytes(result)
        if not 0x21<=value<=0x7e:raise ValueError('Invalid ASCII import name')
        result.append(value)
    raise ValueError('Import name exceeds limit')


def retained_import_table(pe,rva,sections,max_descriptors=128,max_symbols=4096):
    if pe.OPTIONAL_HEADER.Magic!=0x10b or pe.FILE_HEADER.Machine!=0x14c:raise ValueError('Retained-import path supports x86 PE32 only')
    imports=[];total=0
    for index in range(max_descriptors+1):
        descriptor=file_backed_data(pe,rva+index*20,20,sections)
        if descriptor==bytes(20):
            if not imports:raise ValueError('Empty import table')
            return {'rva':rva,'descriptor_bytes':(index+1)*20,'descriptors':imports,'symbol_count':total}
        if index==max_descriptors:raise ValueError('Import descriptor count exceeds limit')
        lookup,timestamp,forwarder,name,iat=struct.unpack('<IIIII',descriptor)
        if not iat or not name:raise ValueError('Incomplete import descriptor')
        dll=c_string(pe,name,sections,128)
        if not re.fullmatch(rb'[A-Za-z0-9_.-]+\.(?:dll|ocx|drv)',dll,re.I):raise ValueError('Invalid import module')
        values=[];symbols=[]
        for symbol_index in range(max_symbols-total+1):
            raw=file_backed_data(pe,(lookup or iat)+symbol_index*4,4,sections)
            value=struct.unpack('<I',raw)[0]
            file_backed_data(pe,iat+symbol_index*4,4,sections)
            if value==0:break
            if total+len(values)>=max_symbols:raise ValueError('Import symbol count exceeds limit')
            if value&0x80000000:
                if value&0x7fff0000 or not value&0xffff:raise ValueError('Invalid import ordinal')
                symbol='#'+str(value&0xffff)
            else:
                file_backed_data(pe,value,2,sections)
                symbol=c_string(pe,value+2,sections,512).decode('ascii')
            values.append(value);symbols.append(symbol)
        else:raise ValueError('Unterminated import thunks')
        if not values:raise ValueError('Empty import descriptor')
        total+=len(values)
        imports.append({'dll':dll.decode('ascii'),'lookup_rva':lookup or iat,'iat_rva':iat,'lookup_values':values,'symbols':symbols})
    raise ValueError('Unterminated import table')


def find_retained_import_table(memory,sections,observed,max_scan_bytes=1048576,allow_observed_superset=False):
    """Find one strict table matching all dynamically observed import symbols.

    Uses only current specimen memory. Ambiguous or incomplete candidates fall
    back to ordinary reconstruction; a paired original is never consulted.
    """
    from types import SimpleNamespace as N
    expected=set();bindings={}
    for module,functions in observed.items():
        for name,address in functions:
            symbol=str(name)
            if '/' in symbol:
                try:symbol='#'+str(int(symbol.rsplit('/',1)[-1]))
                except ValueError:return None
            identity=(str(module).split('#')[0].lower(),symbol)
            expected.add(identity);bindings.setdefault(identity,set()).add(address)
    if not expected:return None
    mapped=[N(VirtualAddress=s.VirtualAddress,Misc_VirtualSize=max(s.VirtualSize,s.SizeOfRawData),SizeOfRawData=max(s.VirtualSize,s.SizeOfRawData)) for s in sections]
    pe=N(OPTIONAL_HEADER=N(Magic=0x10b),FILE_HEADER=N(Machine=0x14c),get_data=lambda rva,size:memory[rva:rva+size])
    matches=[]
    for offset in range(0,min(len(memory)-19,max_scan_bytes),4):
        lookup,timestamp,forwarder,name,iat=struct.unpack_from('<IIIII',memory,offset)
        if not 0<name<len(memory) or not 0<iat<len(memory) or lookup>=len(memory):continue
        module=memory[name:min(name+128,len(memory))].split(b'\0',1)[0]
        if not module.lower().endswith((b'.dll',b'.ocx',b'.drv')):continue
        try:table=retained_import_table(pe,offset,mapped)
        except (ValueError,struct.error):continue
        actual={(d['dll'].lower(),symbol) for d in table['descriptors'] for symbol in d['symbols']}
        if actual==expected or (allow_observed_superset and actual and actual<expected):
            resolved=True
            for descriptor in table['descriptors']:
                for index,symbol in enumerate(descriptor['symbols']):
                    value=struct.unpack_from('<I',memory,descriptor['iat_rva']+index*4)[0]
                    if value not in bindings[(descriptor['dll'].lower(),symbol)]:resolved=False
            if resolved:matches.append(table)
        if len(matches)>1 and not allow_observed_superset:return None
    if allow_observed_superset and matches:
        # A descriptor-table suffix is also parseable. Prefer a unique maximal
        # table after all of its live IAT bindings have been corroborated.
        largest=max(table['symbol_count'] for table in matches)
        matches=[table for table in matches if table['symbol_count']==largest]
    return matches[0] if len(matches)==1 else None


def normalize_rebuilt_terminator(data):
    """Terminate this backend's counted descriptors without overwriting live names.

    The caller supplies a reconstructed PE, not live CPU memory. The count comes
    from the backend's declared directory size; every descriptor and binding must
    validate before any output bytes are returned.
    """
    import pefile
    pe=pefile.PE(data=data,fast_load=False)
    try:
        from unpacker.reconstruction import import_descriptor_consistency
        existing=import_descriptor_consistency(pe)
        if existing['passed']:
            return data,{'already_valid':True,**existing}
        directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
        rva,size=directory.VirtualAddress,directory.Size
        if not rva or not 0<size<=128*20 or size%20:raise ValueError('Invalid rebuilt descriptor count')
        end=rva+size;previous=file_backed_data(pe,end,20,pe.sections)
        if not pe.set_bytes_at_rva(end,bytes(20)):raise ValueError('Descriptor terminator is not writable')
        table=retained_import_table(pe,rva,pe.sections)
        if table['descriptor_bytes']!=size+20:raise ValueError('Rebuilt descriptor count differs from strict table')
        protected=[]
        for index,descriptor in enumerate(table['descriptors']):
            values=descriptor['lookup_values'];width=4*(len(values)+1)
            protected.extend([(descriptor['lookup_rva'],width),(descriptor['iat_rva'],width)])
            raw=file_backed_data(pe,rva+index*20,20,pe.sections)
            name=struct.unpack('<IIIII',raw)[3];protected.append((name,len(descriptor['dll'])+1))
            for symbol,value in zip(descriptor['symbols'],values):
                if not value&0x80000000:protected.append((value,len(symbol.encode('ascii'))+3))
            for position,value in enumerate(values+[0]):
                if file_backed_data(pe,descriptor['iat_rva']+position*4,4,pe.sections)!=struct.pack('<I',value):raise ValueError('Rebuilt IAT is not loader-ready')
        if any(start<end+20 and end<start+length for start,length in protected) and previous!=bytes(20):
            raise ValueError('Descriptor terminator overlaps import payload')
        directory.Size=size+20
        output=bytearray(pe.write());offset=pe.get_offset_from_rva(end)
        # pefile.write() also serializes cached malformed descriptor structures.
        # Apply the validated zero terminator after that serialization step.
        output[offset:offset+20]=bytes(20)
        return bytes(output),{'descriptors':len(table['descriptors']),'symbols':table['symbol_count'],'terminator_rva':end}
    finally:pe.close()
