"""Verified resident-core API entry routing; no host library execution.

Use actual exports of already-mapped dependency images. No invented PE header,
module pointer, new API semantics or general forwarder/ordinal resolver is added.
"""
from pathlib import Path
import struct

FILES={'kernel32.dll':'kernel32.dll','kernelbase.dll':'KernelBase.dll','ntdll.dll':'ntdll.dll'}
MAX_BINDINGS=512


def _source(engine,row):
    import pefile,unipacker
    name=row['name'].lower();cache=getattr(engine,'_unpacker_core_export_sources',None)
    if cache is None:cache={};engine._unpacker_core_export_sources=cache
    if name not in cache:
        source=pefile.PE(str(Path(unipacker.__file__).resolve().parent/'DLLs'/FILES[name]))
        if source.OPTIONAL_HEADER.SizeOfImage!=row['image_size']:
            raise ValueError('Core image metadata does not match resident module')
        cache[name]=(source,source.get_memory_mapped_image(ImageBase=row['base']))
    return cache[name]


def _plan(engine,row,symbol):
    source,image=_source(engine,row);base=row['base']
    symbols=getattr(getattr(source,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])
    matches=[e for e in symbols if e.name==symbol.encode('ascii')]
    if len(matches)!=1 or matches[0].forwarder:raise ValueError('Core export is absent, ambiguous or forwarded')
    rva=matches[0].address;exports=source.DIRECTORY_ENTRY_EXPORT.struct
    index=matches[0].ordinal-exports.Base;table=exports.AddressOfFunctions
    if not 0<=index<exports.NumberOfFunctions<=8192 or not 0<table<row['image_size'] or table+4*(index+1)>row['image_size']:
        raise ValueError('Core export address-table bounds are invalid')
    if struct.unpack('<I',engine.uc.mem_read(base+table+index*4,4))[0]!=rva:
        raise ValueError('Resident core export address table differs from source metadata')
    section=source.get_section_by_rva(rva)
    following=min((e.address for e in symbols if e.address>rva),default=row['image_size'])
    if (section is None or not section.Characteristics&0x20000000 or rva<4096 or
        rva+8>row['image_size'] or following-rva<8):
        raise ValueError('Core export has no bounded executable thunk extent')
    address=base+rva
    if not any(lo<=address and address+7<=hi and flags&4 for lo,hi,flags in engine.uc.mem_regions()):
        raise ValueError('Core export is not mapped executable')
    shim=b'\x8b\x04\x25'+struct.pack('<I',engine.HOOK_ADDR)+b'\xc3'
    actual=bytes(engine.uc.mem_read(address,8))
    if actual!=image[rva:rva+8] and not (actual==shim and engine.apicall_handler.hooks.get(address)==symbol):
        raise ValueError('Resident core export differs from its verified source/interposition')
    return address,rva,shim


def _commit(engine,address,name,symbol,shim):
    handler=engine.apicall_handler;owners=getattr(handler,'module_for_function',None)
    original_owner=owners.get(symbol) if isinstance(owners,dict) else None
    handler.add_hook(engine.uc,symbol,name,address)
    # Registering an alias must not relabel an existing import's DLL provenance.
    if original_owner is not None:owners[symbol]=original_owner
    entries=getattr(engine,'_unpacker_core_import_entries',None)
    if entries is None:entries={};engine._unpacker_core_import_entries=entries
    entries[address]=(symbol,shim)


def bind_initial_module_handle(engine,input_data):
    import pefile
    rows={r['name'].lower():r for r in engine._unpacker_loader_lists['module_images']}
    parser=pefile.PE(data=input_data,fast_load=True)
    parser.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    pending=[]
    for descriptor in getattr(parser,'DIRECTORY_ENTRY_IMPORT',[]):
        name=descriptor.dll.decode('ascii').lower()
        if name not in FILES:continue
        for entry in descriptor.imports:
            if entry.name!=b'GetModuleHandleA':continue
            if name not in rows:raise ValueError('Core import module is not resident')
            symbol='GetModuleHandleA';row=rows[name]
            address,rva,shim=_plan(engine,row,symbol)
            original=struct.unpack('<I',engine.uc.mem_read(entry.address,4))[0]
            if engine.apicall_handler.hooks.get(original)!=symbol:
                raise ValueError('Initial IAT no longer matches its declared bootstrap import')
            pending.append((entry.address,address,name,symbol,original,rva,shim))
    records=[]
    for slot,address,name,symbol,original,rva,shim in pending:
        _commit(engine,address,name,symbol,shim)
        engine.uc.mem_write(slot,struct.pack('<I',address))
        records.append({'module':name,'symbol':symbol,'iat_slot':slot,'previous_scratch_thunk':original,
                        'address':address,'export_rva':rva,'source':'already_mapped_dependency_export'})
    return {'scope':'initial_named_GetModuleHandleA_core_imports_only','bindings':records,
            'general_core_resolver_forwarders_ordinals':'unchanged/not_added','native_host_execution':False}


def install_modeled_core_exports(engine,model):
    rows=[r for r in engine._unpacker_loader_lists['module_images'] if r['name'].lower() in FILES]
    plans={};ambiguous=set();skipped=[]
    for row in rows:
        name=row['name'].lower()
        try:source,_=_source(engine,row)
        except ValueError as exc:
            skipped.append({'module':name,'reason':str(exc)});continue
        names=sorted({e.name.decode('ascii') for e in source.DIRECTORY_ENTRY_EXPORT.symbols if e.name and e.name.isascii()})
        for symbol in names:
            if symbol not in model.functions:continue  # No new semantic success stub.
            try:address,rva,shim=_plan(engine,row,symbol)
            except ValueError as exc:
                if len(skipped)<128:skipped.append({'module':name,'symbol':symbol,'reason':str(exc)})
                continue
            if address in plans and plans[address][1]!=symbol:
                ambiguous.add(address);continue
            plans[address]=(name,symbol,rva,shim)
            if len(plans)>MAX_BINDINGS:raise ValueError('Modeled core export binding budget exceeded')
    records=[]
    for address,(name,symbol,rva,shim) in sorted(plans.items()):
        if address in ambiguous:
            if len(skipped)<128:skipped.append({'module':name,'symbol':symbol,'reason':'Ambiguous modeled aliases share an entry'})
            continue
        _commit(engine,address,name,symbol,shim)
        records.append({'module':name,'symbol':symbol,'address':address,'export_rva':rva})
    return {'scope':'already_implemented_API_semantics_at_verified_core_export_entries',
            'bindings':records,'skipped':skipped,'max_bindings':MAX_BINDINGS,
            'forwarders_ordinals_native_dll_initializers':'not_added','native_host_execution':False}


def call_matches_binding(engine,address,name,uc):
    expected=getattr(engine,'_unpacker_core_import_entries',{}).get(address)
    return expected is None or (name==expected[0] and bytes(uc.mem_read(address,8))==expected[1])
