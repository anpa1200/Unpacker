"""Guest-only metadata/dispatch tests; no external DLL or specimen execution."""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_ESP,UC_X86_REG_EIP
from test_loader_lists import fixture as sparse_fixture
from unpacker.loader_lists import install_loader_lists
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI
from unpacker.guest_desktop_modules import DesktopModules


def fixture(collision=False):
    sparse=sparse_fixture();uc=Uc(UC_ARCH_X86,UC_MODE_32)
    for lo,hi,flags in sparse.uc.regions:uc.mem_map(lo,hi-lo+1,flags)
    for address,value in sparse.uc.data.items():uc.mem_write(address,bytes([value]))
    uc.mem_map(0x100000,0x10000,7)
    if collision:uc.mem_map(0x61000000,4096,3)
    handler=N(module_handles={},load_library_counter={},hooks={},module_for_function={},alloc_sizes={},atn={},ntp={})
    engine=N(uc=uc,PEB_BASE=sparse.PEB_BASE,HOOK_ADDR=0x104000,
             sample=N(BASE_ADDR=0x400000,dllname_to_functionlist={}),apicall_handler=handler,apicall_counter={})
    engine._unpacker_loader_lists=install_loader_lists(engine);engine.stop=lambda:None
    model=SelfFileModel(engine,b'benign',32*1024*1024)
    return model,uc


def installed():
    model,uc=fixture();model.desktop_modules=DesktopModules(model);model.install({})
    return model,uc


def call(model,uc,name,args,address=0):
    esp=0x100800;uc.mem_write(esp,struct.pack('<'+'I'*(len(args)+1),0x401000,*args))
    result=model.handler.apicall(address,name,uc,esp,False)
    return result


def string(uc,value,wide=False):
    pointer=0x100100;uc.mem_write(pointer,(value+'\0').encode('utf-16le' if wide else 'ascii'));return pointer


def test_resident_views_have_actual_readable_bases_and_complete_loader_rings():
    model,uc=installed();manager=model.desktop_modules
    assert len(manager.views)==11 and len(manager.symbols)>3000
    rows=model.engine._unpacker_loader_lists['module_images'];assert len(rows)==15
    for row in rows:assert uc.mem_read(row['base'],2)==b'MZ'
    value,esp=call(model,uc,'GetModuleHandleA',[string(uc,'USER32')])
    assert value==manager.views['user32.dll']['base'] and esp==0x100804
    assert manager.refs[value]==1
    ldr=struct.unpack('<I',uc.mem_read(model.engine.PEB_BASE+12,4))[0]
    for offset in [0x0c,0x14,0x1c]:
        head=ldr+offset;node=struct.unpack('<I',uc.mem_read(head,4))[0];seen=[]
        while node!=head:
            assert node not in seen and len(seen)<16;seen.append(node)
            next_node=struct.unpack('<I',uc.mem_read(node,4))[0]
            assert struct.unpack('<I',uc.mem_read(next_node+4,4))[0]==node
            node=next_node
        assert len(seen)==(14 if offset==0x1c else 15)


def test_load_query_and_free_keep_stable_handles_and_distinct_reference_counts():
    model,uc=installed();p=string(uc,'user32.dll')
    base,_=call(model,uc,'LoadLibraryA',[p]);manager=model.desktop_modules
    assert manager.refs[base]==2
    assert call(model,uc,'GetModuleHandleA',[p])[0]==base and manager.refs[base]==2
    assert call(model,uc,'FreeLibrary',[base])[0]==1 and manager.refs[base]==1
    with pytest.raises(UnsupportedAPI,match='pinned'):call(model,uc,'FreeLibrary',[base])


def test_unicode_load_and_reserved_loadex_flags_are_explicit():
    model,uc=installed();p=string(uc,'gdi32.dll',True)
    base,_=call(model,uc,'LoadLibraryW',[p])
    assert call(model,uc,'GetModuleHandleW',[p])[0]==base
    assert call(model,uc,'LoadLibraryExW',[p,0,0x800])[0]==base
    with pytest.raises(UnsupportedAPI,match='Only ordinary'):call(model,uc,'LoadLibraryExW',[p,0,2])


def test_published_but_unmodeled_function_resolves_then_fails_when_invoked():
    model,uc=installed();base=model.desktop_modules.views['user32.dll']['base']
    address,_=call(model,uc,'GetProcAddress',[base,string(uc,'DrawTextA')])
    assert address in model.desktop_modules.symbols
    with pytest.raises(UnsupportedAPI,match='execution semantics'):call(model,uc,'DrawTextA',[0]*5,address)


def test_managed_entry_metadata_resolves_but_never_claims_clr_execution():
    model,uc=installed();base=model.desktop_modules.views['mscoree.dll']['base']
    address,_=call(model,uc,'GetProcAddress',[base,string(uc,'_CorExeMain')])
    assert address in model.desktop_modules.symbols
    with pytest.raises(UnsupportedAPI,match='execution semantics'):call(model,uc,'_CorExeMain',[],address)


def test_ole_module_has_a_real_guest_image_but_object_activation_is_not_dummy_success():
    model,uc=installed();view=model.desktop_modules.views['ole32.dll']
    base,_=call(model,uc,'GetModuleHandleA',[string(uc,'ole32.dll')])
    assert base==view['base'] and uc.mem_read(base,2)==b'MZ'
    address,_=call(model,uc,'GetProcAddress',[base,string(uc,'CoCreateInstance')])
    assert address in model.desktop_modules.symbols
    with pytest.raises(UnsupportedAPI,match='execution semantics'):
        call(model,uc,'CoCreateInstance',[0]*5,address)


def test_automation_exports_do_not_claim_unimplemented_variant_semantics():
    model,uc=installed();view=model.desktop_modules.views['oleaut32.dll']
    address,_=call(model,uc,'GetProcAddress',[view['base'],string(uc,'VariantClear')])
    uc.mem_write(0x100300,b'unchanged')
    with pytest.raises(UnsupportedAPI,match='execution semantics'):
        call(model,uc,'VariantClear',[0x100300],address)
    assert uc.mem_read(0x100300,9)==b'unchanged'


@pytest.mark.parametrize('copied',[False,5,8])
def test_implemented_export_and_its_copy_execute_the_correct_model(copied):
    model,uc=installed();view=model.desktop_modules.views['user32.dll'];pointer=0x100300
    uc.mem_write(pointer,b'ab');address=view['exports']['CharUpperBuffA']
    if copied:
        uc.mem_write(0x100500,bytes(uc.mem_read(address,copied)));address=0x100500
    uc.mem_write(0x100800,struct.pack('<III',0x100900,pointer,2));uc.reg_write(UC_X86_REG_ESP,0x100800)
    uc.reg_write(UC_X86_REG_EAX,0xdeadbeef)
    uc.emu_start(address,0x100900,timeout=100000,count=8)
    assert uc.reg_read(UC_X86_REG_EAX)==2
    assert uc.reg_read(UC_X86_REG_ESP)==0x10080c and uc.mem_read(pointer,2)==b'AB'
    assert model.engine.apicall_counter=={'CharUpperBuffA':1}
    assert model.desktop_modules.copied_trap_calls==int(bool(copied))


def test_guest_interposition_jump_to_copied_api_keeps_dispatch_and_stack_semantics():
    model,uc=installed();manager=model.desktop_modules
    address=manager.views['user32.dll']['exports']['CharUpperBuffA'];copied=0x100500;pointer=0x100300
    uc.mem_write(copied,bytes(uc.mem_read(address,8)))
    uc.mem_write(address,b'\xe9'+struct.pack('<i',copied-address-5))
    uc.mem_write(pointer,b'ab');uc.mem_write(0x100800,struct.pack('<III',0x100900,pointer,2))
    uc.reg_write(UC_X86_REG_ESP,0x100800);events=[]
    uc.hook_add(UC_HOOK_CODE,lambda uc,pc,size,data:events.append((pc,size,manager.is_dispatch_site(uc,pc,size))))
    uc.emu_start(address,0x100900,timeout=100000,count=8)
    assert uc.mem_read(pointer,2)==b'AB' and uc.reg_read(UC_X86_REG_EAX)==2
    assert uc.reg_read(UC_X86_REG_ESP)==0x10080c
    assert any(pc==address and dispatch for pc,size,dispatch in events)
    assert any(pc==copied and dispatch for pc,size,dispatch in events)
    assert uc.reg_read(UC_X86_REG_ESP)==0x10080c
    assert manager.trap_calls==manager.copied_trap_calls==1


def test_copied_unmodeled_api_stops_explicitly_without_dummy_success():
    model,uc=installed();address=model.desktop_modules.views['user32.dll']['exports']['DrawTextA']
    uc.mem_write(0x100500,bytes(uc.mem_read(address,8)));uc.reg_write(UC_X86_REG_ESP,0x100800)
    uc.mem_write(0x100800,struct.pack('<IIIIII',0x100900,0,0,0,0,0));uc.reg_write(UC_X86_REG_EAX,123)
    try:uc.emu_start(0x100500,0x100900,timeout=100000,count=8)
    except UcError:pass
    assert model.unsupported[-1]['name']=='DrawTextA'
    assert 'execution semantics' in model.engine._unpacker_callback_error
    assert uc.reg_read(UC_X86_REG_EAX)==123 and uc.reg_read(UC_X86_REG_EIP)!=0x100900
    assert model.engine.apicall_counter=={}


@pytest.mark.parametrize('raw',[b'\x0f\x0b'+bytes(2)+b'\xc3',b'\x0f\x0b'+struct.pack('<H',1)+b'\x90'])
def test_unknown_or_corrupt_trap_does_not_invoke_any_api(raw):
    model,uc=installed();uc.mem_write(0x100500,raw)
    assert not model.desktop_modules.is_dispatch_site(uc,0x100500,0xffffffff)
    with pytest.raises(UcError):uc.emu_start(0x100500,0x100900,timeout=100000,count=8)
    assert model.engine.apicall_counter=={} and model.desktop_modules.trap_calls==0


def test_dispatch_budget_stops_instead_of_continuing_in_guest():
    model,uc=installed();manager=model.desktop_modules;manager.trap_calls=65536
    address=manager.views['user32.dll']['exports']['CharUpperBuffA']
    uc.reg_write(UC_X86_REG_ESP,0x100800)
    try:uc.emu_start(address,0x100900,timeout=100000,count=8)
    except UcError:pass
    assert 'dispatch budget' in model.engine._unpacker_callback_error and model.engine.apicall_counter=={}


def test_crt_data_exports_share_storage_with_the_crt_pointer_api():
    model,uc=installed();view=model.desktop_modules.views['msvcrt.dll']
    address,_=call(model,uc,'GetProcAddress',[view['base'],string(uc,'_acmdln')])
    pointer=struct.unpack('<I',uc.mem_read(address,4))[0]
    assert pointer==model.command_line(uc,False) and model.command_line_cell(uc)==address
    assert uc.mem_read(pointer,len(model.PATH)+1)==model.PATH+b'\0'
    assert address not in model.engine.apicall_handler.hooks
    assert any(lo<=address<=hi and flags==3 for lo,hi,flags in uc.mem_regions())


@pytest.mark.parametrize('query',[7,'_fmode'])
def test_unknown_exports_and_native_ordinals_never_receive_dummy_success(query):
    model,uc=installed();base=model.desktop_modules.views['msvcrt.dll']['base']
    pointer=query if isinstance(query,int) else string(uc,query)
    with pytest.raises(UnsupportedAPI):call(model,uc,'GetProcAddress',[base,pointer])


@pytest.mark.parametrize('symbol',['InventedExportName','','virtualalloc'])
def test_absent_case_sensitive_export_returns_null_and_does_not_invent_an_import(symbol):
    model,uc=installed();base=model.desktop_modules.views['user32.dll']['base']
    assert call(model,uc,'GetProcAddress',[base,string(uc,symbol)])==(0,0x100808)
    assert model.last_error==127 and model.unsupported==[]
    assert model.engine.sample.dllname_to_functionlist=={}


def test_absent_module_load_is_a_real_failure_with_no_handle_or_reference():
    model,uc=installed();refs=dict(model.desktop_modules.refs)
    assert call(model,uc,'LoadLibraryA',[string(uc,'absent.dll')])==(0,0x100804)
    assert model.last_error==126 and model.desktop_modules.refs==refs and model.handler.module_handles=={}
    assert call(model,uc,'GetProcAddress',[0,string(uc,'Missing')])==(0,0x100808)


def test_resident_code_protection_has_an_actual_reservation_and_guest_enforcement():
    model,uc=installed();address=model.desktop_modules.views['user32.dll']['exports']['CharUpperBuffA']
    assert model.protection.protect(uc,address,5,0x40,0x100400)==1
    assert struct.unpack('<I',uc.mem_read(0x100400,4))[0]==0x20
    assert any(lo<=address<=hi and flags==7 for lo,hi,flags in uc.mem_regions())
    assert model.protection.protect(uc,address,5,0x20,0x100400)==1
    assert any(lo<=address<=hi and flags==5 for lo,hi,flags in uc.mem_regions())


def test_crt_initial_environment_is_data_and_narrow_startup_publishes_its_empty_vector():
    model,uc=installed();exports=model.desktop_modules.views['msvcrt.dll']['data_exports']
    for symbol in ['__initenv','__winitenv']:
        assert bytes(uc.mem_read(exports[symbol],4))==bytes(4)
        assert exports[symbol] not in model.handler.hooks
    model.global_alloc=lambda uc,flags,size:0x102000
    uc.mem_write(0x100600,bytes(16))
    assert model.crt_startup.getmainargs(uc,0x100600,0x100604,0x100608,0,0x10060c)==0
    assert uc.mem_read(exports['__initenv'],4)==uc.mem_read(0x100608,4)
    vector=struct.unpack('<I',uc.mem_read(exports['__initenv'],4))[0]
    assert uc.mem_read(vector,4)==bytes(4) and uc.mem_read(exports['__winitenv'],4)==bytes(4)


def test_cdecl_trap_preserves_caller_owned_arguments():
    model,uc=installed();address=model.desktop_modules.views['msvcrt.dll']['exports']['strlen']
    pointer=string(uc,'benign');uc.mem_write(0x100800,struct.pack('<II',0x100900,pointer))
    uc.reg_write(UC_X86_REG_ESP,0x100800);uc.emu_start(address,0x100900,timeout=100000,count=8)
    assert uc.reg_read(UC_X86_REG_EAX)==6 and uc.reg_read(UC_X86_REG_ESP)==0x100804
    assert struct.unpack('<I',uc.mem_read(0x100804,4))[0]==pointer


def test_trap_schedules_a_real_guest_initializer_and_resumes_its_cdecl_caller():
    model,uc=installed();address=model.desktop_modules.views['msvcrt.dll']['exports']['_initterm']
    uc.mem_write(0x100300,b'\xb8\x09\x00\x00\x00\xc3')
    uc.mem_write(0x100400,struct.pack('<I',0x100300))
    uc.mem_write(0x100800,struct.pack('<III',0x100900,0x100400,0x100404));uc.reg_write(UC_X86_REG_ESP,0x100800)
    def callback_hook(uc,pc,size,data):
        if pc in model.handler.hooks:
            value,esp=model.handler.apicall(pc,model.handler.hooks[pc],uc,uc.reg_read(UC_X86_REG_ESP),False)
            if value is not None:uc.mem_write(model.engine.HOOK_ADDR,struct.pack('<I',value))
            uc.reg_write(UC_X86_REG_ESP,esp)
    uc.hook_add(UC_HOOK_CODE,callback_hook)
    uc.emu_start(address,0x100900,timeout=100000,count=16)
    assert model.callbacks.calls==model.callbacks.completed==1 and not model.callbacks.frames
    assert uc.reg_read(UC_X86_REG_ESP)==0x100804 and uc.reg_read(UC_X86_REG_EIP)==0x100900


def test_mapping_collision_fails_before_mutating_guest_memory_or_loader_state():
    model,uc=fixture(True);before=list(uc.mem_regions());state=bytes(uc.mem_read(0x202000,0x3000))
    with pytest.raises(UnsupportedAPI,match='already mapped'):DesktopModules(model)
    assert list(uc.mem_regions())==before and uc.mem_read(0x202000,0x3000)==state
    assert model.handler.hooks=={}


def test_guest_modified_export_entry_is_rejected_instead_of_ignoring_interposition():
    model,uc=installed();address=model.desktop_modules.views['user32.dll']['exports']['MessageBoxA']
    uc.mem_write(address,b'\xe9'+bytes(4))
    with pytest.raises(UnsupportedAPI,match='interposition'):call(model,uc,'MessageBoxA',[0]*4,address)


def test_export_lookup_budget_is_bounded_and_observations_remain_module_scoped():
    model,uc=installed();manager=model.desktop_modules;view=manager.views['user32.dll']
    p=string(uc,'MessageBoxA');address,_=call(model,uc,'GetProcAddress',[view['base'],p])
    assert model.engine.sample.dllname_to_functionlist['user32.dll#0']==[('MessageBoxA',address)]
    manager.lookups=8192
    with pytest.raises(UnsupportedAPI,match='lookup budget'):call(model,uc,'GetProcAddress',[view['base'],p])
