"""Known-original PE acceptance gates. Static equality is not behavioral proof."""
import hashlib


def import_symbols(pe):
    return sorted((entry.dll.decode('ascii','replace').lower(),
                   item.name.decode('ascii','replace') if item.name else '#'+str(item.ordinal))
                  for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]) for item in entry.imports)


def entry_mapping(pe):
    rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        offset=rva-section.VirtualAddress
        if 0<=offset<min(section.Misc_VirtualSize or section.SizeOfRawData,section.SizeOfRawData):
            return {'rva':rva,'raw_offset':section.PointerToRawData+offset,
                    'file_backed':True,'executable':bool(section.Characteristics&0x20000000)}
    return {'rva':rva,'raw_offset':None,'file_backed':False,'executable':False}


def import_iat_consistency(pe,include_details=False):
    """Check loader-ready thunk values as well as parser-visible symbol names."""
    width=8 if pe.OPTIONAL_HEADER.Magic==0x20b else 4
    checked=0;differences=[];details=[]
    for descriptor in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
        first=descriptor.struct.FirstThunk
        lookup=descriptor.struct.OriginalFirstThunk or first
        for index,item in enumerate(descriptor.imports):
            actual=pe.get_data(first+index*width,width)
            expected=pe.get_data(lookup+index*width,width)
            checked+=1
            if len(actual)!=width or len(expected)!=width or actual!=expected:
                if len(differences)<128:differences.append(first+index*width)
                if include_details and len(details)<16:
                    details.append({'rva':first+index*width,'actual':actual.hex(),'expected':expected.hex(),'kind':'symbol'})
        terminator=pe.get_data(first+len(descriptor.imports)*width,width)
        if terminator!=bytes(width):
            if len(differences)<128:differences.append(first+len(descriptor.imports)*width)
            if include_details and len(details)<16:
                details.append({'rva':first+len(descriptor.imports)*width,'actual':terminator.hex(),'expected':bytes(width).hex(),'kind':'terminator'})
    result={'passed':not differences,'checked_symbols':checked,'inconsistent_iat_rvas':differences}
    if include_details:result['details']=details
    return result


def import_descriptor_consistency(pe):
    """Do not let a best-effort parser hide malformed trailing descriptors."""
    from unpacker.pe_rebuilder.imports import file_backed_data,c_string
    parsed=getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])
    try:
        directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
        if not directory.VirtualAddress and not directory.Size:
            return {'passed':not parsed,'descriptors':0}
        if not directory.VirtualAddress:raise ValueError('Import directory has no address')
        import struct
        total=0
        for index in range(129):
            raw=file_backed_data(pe,directory.VirtualAddress+index*20,20,pe.sections)
            if raw==bytes(20):
                if index!=len(parsed):raise ValueError('Parsed descriptor count differs from raw table')
                if directory.Size<index*20:raise ValueError('Declared import directory is truncated')
                return {'passed':True,'descriptors':index,'symbols':total}
            if index==128 or index>=len(parsed):raise ValueError('Unparsed or excessive import descriptor')
            lookup,stamp,forwarder,name,first=struct.unpack('<IIIII',raw)
            entry=parsed[index]
            if first!=entry.struct.FirstThunk or lookup!=entry.struct.OriginalFirstThunk:raise ValueError('Parsed descriptor differs from raw table')
            if not first or c_string(pe,name,pe.sections,256)!=entry.dll or not entry.imports:raise ValueError('Incomplete import descriptor')
            total+=len(entry.imports)
            if total>4096:raise ValueError('Import symbol budget exceeded')
    except Exception as exc:
        return {'passed':False,'reason':str(exc)[:160]}
    return {'passed':False,'reason':'Unterminated import descriptor table'}


def compare_pe_reference(candidate,original):
    sections=[]
    for section in original.sections:
        if not section.Characteristics&0x20000000 or not section.SizeOfRawData:continue
        count=min(section.Misc_VirtualSize or section.SizeOfRawData,section.SizeOfRawData)
        expected=original.get_data(section.VirtualAddress,count)
        actual=candidate.get_data(section.VirtualAddress,count)
        sections.append({'rva':section.VirtualAddress,'bytes_expected':count,'bytes_compared':len(actual),
            'original_sha256':hashlib.sha256(expected).hexdigest(),'output_sha256':hashlib.sha256(actual).hexdigest(),
            'different_bytes':sum(a!=b for a,b in zip(expected,actual))+abs(len(expected)-len(actual)),
            'first_difference_rvas':[section.VirtualAddress+i for i,(a,b) in enumerate(zip(expected,actual)) if a!=b][:32],
            'match':count>0 and len(expected)==count and len(actual)==count and expected==actual})
    actual_imports=import_symbols(candidate);expected_imports=import_symbols(original)
    iat=import_iat_consistency(candidate)
    descriptors=import_descriptor_consistency(candidate)
    actual_entry=entry_mapping(candidate);expected_entry=entry_mapping(original)
    missing=sorted(set(expected_imports)-set(actual_imports));extra=sorted(set(actual_imports)-set(expected_imports))
    gates={'executable_bytes':bool(sections) and all(s['match'] for s in sections),
           'entry_rva':actual_entry['rva']==expected_entry['rva'],
           'entry_mapping':actual_entry['file_backed'] and actual_entry['executable'] and expected_entry['file_backed'] and expected_entry['executable'],
           'imports':actual_imports==expected_imports,'iat_loader_ready':iat['passed'],'import_descriptors':descriptors['passed'],
           'machine':candidate.FILE_HEADER.Machine==original.FILE_HEADER.Machine}
    return {'passed':all(gates.values()),'gates':gates,'iat_consistency':iat,'import_descriptor_table':descriptors,'executable_sections':sections,
            'entry':actual_entry,'original_entry':expected_entry,'import_count':len(actual_imports),
            'original_import_count':len(expected_imports),'missing_imports':missing[:128],
            'unexpected_imports':extra[:128],'import_differences_truncated':len(missing)>128 or len(extra)>128,
            'scope':'code_imports_entry_static_only'}
