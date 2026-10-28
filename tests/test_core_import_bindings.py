"""Benign mapped-module identity tests, no DLL code or specimen execution."""
import struct
from types import SimpleNamespace as N
import pefile,pytest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unpacker.core_import_bindings import bind_initial_module_handle,call_matches_binding


def fixture(monkeypatch):
    uc=Uc(UC_ARCH_X86,UC_MODE_32);base=0x755d0000
    uc.mem_map(base,0x3000,7);uc.mem_write(base,b'MZ');uc.mem_write(base+0x1000,b'\x90'*8)
    uc.mem_map(0x401000,4096,3);slot=0x401100;uc.mem_write(slot,struct.pack('<I',0x104004))
    symbols=[N(name=b'GetModuleHandleA',address=0x1000,forwarder=None,ordinal=1),N(name=b'Other',address=0x1020,forwarder=None,ordinal=2)]
    uc.mem_write(base+0x800,struct.pack('<II',0x1000,0x1020))
    section=N(Characteristics=0x60000020)
    image=bytearray(0x3000);image[:2]=b'MZ';image[0x1000:0x1008]=b'\x90'*8
    source=N(OPTIONAL_HEADER=N(SizeOfImage=0x3000),DIRECTORY_ENTRY_EXPORT=N(symbols=symbols,struct=N(Base=1,NumberOfFunctions=2,AddressOfFunctions=0x800)),
             get_section_by_rva=lambda address:section,get_memory_mapped_image=lambda **kwargs:bytes(image))
    imports=N(DIRECTORY_ENTRY_IMPORT=[N(dll=b'kernel32.dll',imports=[N(name=b'GetModuleHandleA',address=slot)])],parse_data_directories=lambda **kwargs:None)
    monkeypatch.setattr(pefile,'PE',lambda *args,**kwargs:imports if 'data' in kwargs else source)
    hooks={0x104004:'GetModuleHandleA'}
    def add_hook(uc,name,module,address):
        uc.mem_write(address,b'\x8b\x04\x25'+struct.pack('<I',0x104000)+b'\xc3');hooks[address]=name
    engine=N(uc=uc,HOOK_ADDR=0x104000,apicall_handler=N(hooks=hooks,add_hook=add_hook),
             _unpacker_loader_lists={'module_images':[{'name':'kernel32.dll','base':base,'image_size':0x3000}]})
    return engine,source,imports,section,slot


def test_initial_pointer_resolves_to_real_export_inside_resident_mz_image(monkeypatch):
    e,source,imports,section,slot=fixture(monkeypatch);result=bind_initial_module_handle(e,b'benign-packed-import-metadata')
    address=struct.unpack('<I',e.uc.mem_read(slot,4))[0]
    assert address==0x755d1000 and bytes(e.uc.mem_read(address&0xffff0000,2))==b'MZ'
    assert e.apicall_handler.hooks[address]=='GetModuleHandleA'
    assert result['bindings'][0]['export_rva']==0x1000 and not result['native_host_execution']
    assert call_matches_binding(e,address,'GetModuleHandleA',e.uc)


@pytest.mark.parametrize('defect,reason',[
    ('missing','absent'),('forwarded','forwarded'),('data','executable'),('short','extent'),
    ('modified','differs'),('wrong_iat','IAT'),('wrong_size','metadata'),('ambiguous','ambiguous'),('wrong_eat','address table'),
])
def test_failed_metadata_validation_changes_neither_iat_nor_core_entry(monkeypatch,defect,reason):
    e,source,imports,section,slot=fixture(monkeypatch)
    if defect=='missing':source.DIRECTORY_ENTRY_EXPORT.symbols=source.DIRECTORY_ENTRY_EXPORT.symbols[1:]
    if defect=='forwarded':source.DIRECTORY_ENTRY_EXPORT.symbols[0].forwarder=b'OTHER.GetModuleHandleA'
    if defect=='data':section.Characteristics=0x40000040
    if defect=='short':source.DIRECTORY_ENTRY_EXPORT.symbols[1].address=0x1004
    if defect=='wrong_eat':e.uc.mem_write(0x755d0800,struct.pack('<I',0x1200))
    if defect=='modified':e.uc.mem_write(0x755d1000,b'\xcc')
    if defect=='wrong_iat':e.uc.mem_write(slot,struct.pack('<I',0x104008))
    if defect=='wrong_size':source.OPTIONAL_HEADER.SizeOfImage=0x4000
    if defect=='ambiguous':source.DIRECTORY_ENTRY_EXPORT.symbols.append(N(name=b'GetModuleHandleA',address=0x1100,forwarder=None))
    before=(bytes(e.uc.mem_read(slot,4)),bytes(e.uc.mem_read(0x755d1000,8)))
    with pytest.raises(ValueError,match=reason):bind_initial_module_handle(e,b'benign')
    assert before==(bytes(e.uc.mem_read(slot,4)),bytes(e.uc.mem_read(0x755d1000,8)))
    assert len(e.apicall_handler.hooks)==1


def test_subsequent_guest_interposition_is_not_silently_bypassed(monkeypatch):
    e,source,imports,section,slot=fixture(monkeypatch);bind_initial_module_handle(e,b'benign')
    e.uc.mem_write(0x755d1000,b'\xcc')
    assert not call_matches_binding(e,0x755d1000,'GetModuleHandleA',e.uc)
    assert call_matches_binding(e,0x104004,'GetModuleHandleA',e.uc)


def test_other_initial_symbols_are_not_claimed_as_canonicalized(monkeypatch):
    e,source,imports,section,slot=fixture(monkeypatch);imports.DIRECTORY_ENTRY_IMPORT[0].imports[0].name=b'Other'
    result=bind_initial_module_handle(e,b'benign')
    assert result['bindings']==[] and struct.unpack('<I',e.uc.mem_read(slot,4))[0]==0x104004


def test_already_modeled_native_export_gets_routing_without_inventing_new_semantics(monkeypatch):
    from unpacker.core_import_bindings import install_modeled_core_exports
    e,source,imports,section,slot=fixture(monkeypatch)
    e.apicall_handler.module_for_function={'Other':'original-owner.dll'}
    facts=install_modeled_core_exports(e,N(functions={'Other':(0,lambda *args:123)}))
    assert len(facts['bindings'])==1 and facts['bindings'][0]['symbol']=='Other'
    assert e.apicall_handler.hooks[0x755d1020]=='Other'
    assert e.apicall_handler.module_for_function['Other']=='original-owner.dll'
    assert struct.unpack('<I',e.uc.mem_read(slot,4))[0]==0x104004


def test_unimplemented_export_has_no_successful_native_entry_binding(monkeypatch):
    from unpacker.core_import_bindings import install_modeled_core_exports
    e,source,imports,section,slot=fixture(monkeypatch)
    facts=install_modeled_core_exports(e,N(functions={}))
    assert facts['bindings']==[] and len(e.apicall_handler.hooks)==1


def test_bad_source_prefix_is_reported_and_not_patched_for_modeled_export(monkeypatch):
    from unpacker.core_import_bindings import install_modeled_core_exports
    e,source,imports,section,slot=fixture(monkeypatch);e.uc.mem_write(0x755d1020,b'\xcc')
    facts=install_modeled_core_exports(e,N(functions={'Other':(0,None)}))
    assert not facts['bindings'] and 'differs' in facts['skipped'][0]['reason']
    assert bytes(e.uc.mem_read(0x755d1020,1))==b'\xcc'


def test_ambiguous_modeled_aliases_do_not_arbitrarily_choose_one_api(monkeypatch):
    from unpacker.core_import_bindings import install_modeled_core_exports
    e,source,imports,section,slot=fixture(monkeypatch)
    source.DIRECTORY_ENTRY_EXPORT.symbols[1].address=0x1000
    e.uc.mem_write(0x755d0804,struct.pack('<I',0x1000))
    facts=install_modeled_core_exports(e,N(functions={'GetModuleHandleA':(1,None),'Other':(0,None)}))
    assert not facts['bindings'] and any('Ambiguous' in r['reason'] for r in facts['skipped'])
    assert len(e.apicall_handler.hooks)==1


def test_core_binding_count_is_bounded_before_native_bytes_are_changed(monkeypatch):
    import unpacker.core_import_bindings as module
    e,source,imports,section,slot=fixture(monkeypatch);monkeypatch.setattr(module,'MAX_BINDINGS',1)
    with pytest.raises(ValueError,match='budget'):
        module.install_modeled_core_exports(e,N(functions={'GetModuleHandleA':(1,None),'Other':(0,None)}))
    assert len(e.apicall_handler.hooks)==1 and bytes(e.uc.mem_read(0x755d1000,8))==b'\x90'*8
