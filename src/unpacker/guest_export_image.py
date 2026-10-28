"""Bounded in-memory PE32 named-export view for the explicit guest model.

This is model metadata and API dispatch code, not a native Windows/Wine DLL.
No DllMain, TLS, imports, forwarders or native ordinal contract is provided.
"""
import re
import struct

PAGE=4096


def build_export_image(name,names,base,return_cell,data_symbols=None,private_data=b'',dispatch_ids=None):
    if name not in {'user32.dll','gdi32.dll','comdlg32.dll','shell32.dll','shlwapi.dll','comctl32.dll','msvcrt.dll','version.dll','mscoree.dll','ole32.dll','oleaut32.dll'}:
        raise ValueError('Unsupported export-view module')
    data_symbols=data_symbols or {}
    if not isinstance(names,(tuple,list)) or not 1<=len(names)<=2048 or len(data_symbols)>64:
        raise ValueError('Invalid export-name count')
    if any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z_?][A-Za-z0-9_@$?]{0,126}',n) for n in [*names,*data_symbols]):
        raise ValueError('Invalid export identifier')
    if len(set(names))!=len(names) or set(names)&set(data_symbols):raise ValueError('Duplicate export identifier')
    if any(not isinstance(v,bytes) or not 1<=len(v)<=256 for v in data_symbols.values()):raise ValueError('Invalid export data')
    if type(base) is not int or base%65536 or not 0<base<2**32-131072:
        raise ValueError('Invalid PE32 module base')
    if type(return_cell) is not int or not 0<return_cell<2**32:raise ValueError('Invalid API return cell')
    functions=sorted(names)
    if dispatch_ids is not None:
        if set(dispatch_ids)!=set(functions) or len(set(dispatch_ids.values()))!=len(functions):
            raise ValueError('Dispatch identifiers must cover each function uniquely')
        if any(type(value) is not int or not 0<value<2**16 for value in dispatch_ids.values()):
            raise ValueError('Invalid dispatch identifier')
    names=sorted([*names,*data_symbols]);count=len(names);edata=bytearray(40+count*10)
    eat=40;pointers=eat+count*4;ordinals=pointers+count*4
    def append(data):
        rva=PAGE+len(edata);edata.extend(data);return rva
    dll_name=append(name.encode('ascii')+b'\0');name_rvas=[append(n.encode('ascii')+b'\0') for n in names]
    data_size=(len(edata)+PAGE-1)&~(PAGE-1);globals_rva=PAGE+data_size
    globals_data=bytearray();data_offsets={}
    for symbol in sorted(data_symbols):
        globals_data.extend(bytes((-len(globals_data))%4));data_offsets[symbol]=len(globals_data)
        globals_data.extend(data_symbols[symbol])
    if not isinstance(private_data,bytes) or len(private_data)>1024:raise ValueError('Invalid private module data')
    private_offset=len(globals_data);globals_data.extend(private_data)
    if len(globals_data)>PAGE:raise ValueError('Export data exceeds one-page budget')
    globals_size=PAGE if globals_data else 0;text_rva=globals_rva+globals_size
    text_size=(len(functions)*8+PAGE-1)&~(PAGE-1);image_size=text_rva+text_size
    if image_size>131072:raise ValueError('Export view exceeds module budget')
    struct.pack_into('<IIHHIIIIIII',edata,0,0,0,0,0,dll_name,1,count,count,PAGE+eat,PAGE+pointers,PAGE+ordinals)
    addresses={};function_indices={name:index for index,name in enumerate(functions)}
    for index,(symbol,rva) in enumerate(zip(names,name_rvas)):
        function_rva=globals_rva+data_offsets[symbol] if symbol in data_symbols else text_rva+function_indices[symbol]*8
        struct.pack_into('<I',edata,eat+index*4,function_rva)
        struct.pack_into('<I',edata,pointers+index*4,rva)
        struct.pack_into('<H',edata,ordinals+index*2,index)
        addresses[symbol]=base+function_rva
    image=bytearray(image_size);image[:2]=b'MZ';struct.pack_into('<I',image,60,128)
    image[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',image,132,0x14c,3 if globals_data else 2,0,0,0,224,0x2102)
    opt=152;struct.pack_into('<H',image,opt,0x10b)
    struct.pack_into('<IIIIII',image,opt+4,text_size,data_size+globals_size,0,0,text_rva,PAGE)
    struct.pack_into('<III',image,opt+28,base,PAGE,PAGE)
    struct.pack_into('<HHHHHH',image,opt+40,6,1,0,0,6,1)
    struct.pack_into('<III',image,opt+56,image_size,PAGE,0)
    struct.pack_into('<HH',image,opt+68,2,0x100)
    struct.pack_into('<IIIIII',image,opt+72,0x100000,PAGE,0x100000,PAGE,0,16)
    struct.pack_into('<II',image,opt+96,PAGE,len(edata))
    sections=[(b'.edata',PAGE,len(edata),data_size,0x40000040)]
    if globals_data:sections.append((b'.data',globals_rva,len(globals_data),globals_size,0xc0000040))
    sections.append((b'.text',text_rva,len(functions)*8,text_size,0x60000020))
    for index,(section,rva,virtual,raw,flags) in enumerate(sections):
        struct.pack_into('<8sIIIIIIHHI',image,opt+224+index*40,section,virtual,rva,raw,rva,0,0,0,0,flags)
    image[PAGE:PAGE+len(edata)]=edata
    thunk=b'\x8b\x04\x25'+struct.pack('<I',return_cell)+b'\xc3'
    if globals_data:image[globals_rva:globals_rva+len(globals_data)]=globals_data
    for index,symbol in enumerate(functions):
        # Five bytes retain the complete dispatch+RET when a guest copies a
        # conventional five-byte entry prologue before installing its jump.
        payload=thunk if dispatch_ids is None else b'\x0f\x0b'+struct.pack('<H',dispatch_ids[symbol])+b'\xc3\x90\x90\x90'
        image[text_rva+index*8:text_rva+(index+1)*8]=payload
    return {'image':bytes(image),'base':base,'size':image_size,'exports':addresses,
            'data_rva':PAGE,'data_size':data_size,'text_rva':text_rva,'text_size':text_size,
            'data_exports':{symbol:addresses[symbol] for symbol in data_symbols},
            'globals_rva':globals_rva,'globals_size':globals_size,
            'private_data_rva':globals_rva+private_offset if private_data else None,
            'export_directory_bytes':len(edata),'ordinal_contract':'model_local_named_export_indices_only'}
