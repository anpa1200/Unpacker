"""Synthetic guest-image handles; no host module loading or native execution."""
import struct
from types import SimpleNamespace as N
import pytest
from test_loader_lists import fixture as loader_fixture
from unpacker.loader_lists import install_loader_lists
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI


def fixture():
    engine=loader_fixture();engine._unpacker_loader_lists=install_loader_lists(engine)
    engine.apicall_handler=N(module_handles={},load_library_counter={})
    engine.sample.dllname_to_functionlist={};stops=[];engine.stop=lambda:stops.append(True)
    model=SelfFileModel(engine,b'benign fixture',65536);legacy=[]
    def backend(handler,uc,esp,log):legacy.append(True);return 0,esp+4
    model.install({'GetModuleHandleA':backend})
    return model,engine.uc,legacy,stops


def call(model,uc,name):
    pointer=0x200100 if name is not None else 0
    if pointer:uc.mem_write(pointer,name+b'\0')
    uc.mem_write(0x200500,struct.pack('<II',0x401234,pointer))
    return model.handler.apicall(0,'GetModuleHandleA',uc,0x200500,False)


@pytest.mark.parametrize('name,expected',[(b'kernel32.dll',0x755d0000),(b'KERNEL32',0x755d0000),
    (b'C:\\Windows\\System32\\KERNEL32.DLL',0x755d0000),(b'ntdll.dll',0x77400000),
    (b'KernelBase.dll',0x73d00000),(b'sample.bin',0x400000),(None,0x400000)])
def test_handles_are_actual_loader_image_bases_with_correct_stdcall(name,expected):
    model,uc,legacy,_=fixture()
    value,esp=call(model,uc,name)
    assert value==expected and uc.mem_read(value,2)==b'MZ'
    assert esp==0x200504 and uc.mem_read(esp,4)==struct.pack('<I',0x401234)
    assert legacy==[]


def test_queries_preserve_old_symbols_and_split_a_new_observation_sequence():
    model,uc,legacy,_=fixture();model.handler.load_library_counter['KERNEL32.DLL']=7
    observations=[('KnownSymbol',0x755d1234)]
    model.engine.sample.dllname_to_functionlist['KERNEL32.DLL#7']=observations
    assert call(model,uc,b'kernel32.dll')[0]==call(model,uc,b'KERNEL32')[0]==0x755d0000
    assert model.handler.load_library_counter=={'KERNEL32.DLL':8}
    assert model.handler.module_handles=={0x755d0000:'KERNEL32.DLL'}
    assert model.engine.sample.dllname_to_functionlist=={'KERNEL32.DLL#7':observations,'KERNEL32.DLL#8':[]}
    assert model.events[-1]['reference_count_change'] is False and legacy==[]


def test_same_hmodule_can_have_separate_contiguous_iat_observation_sequences():
    model,uc,legacy,_=fixture();groups=model.engine.sample.dllname_to_functionlist
    first=call(model,uc,b'kernel32.dll')[0]
    groups['kernel32.dll#0'].append(('StubOnlySymbol',0x104000))
    second=call(model,uc,b'KERNEL32.DLL')[0]
    groups['kernel32.dll#1'].extend([('OriginalOne',0x104008),('OriginalTwo',0x104010)])
    assert first==second==0x755d0000
    assert groups=={'kernel32.dll#0':[('StubOnlySymbol',0x104000)],
                   'kernel32.dll#1':[('OriginalOne',0x104008),('OriginalTwo',0x104010)]}
    assert model.modules.facts()['reference_count_change'] is False and legacy==[]


def test_observation_sequence_collision_never_overwrites_existing_symbols():
    model,uc,_,_=fixture();groups=model.engine.sample.dllname_to_functionlist
    model.handler.load_library_counter['kernel32.dll']=0
    groups.update({'kernel32.dll#0':[('First',123)],'kernel32.dll#1':[('Other',456)]})
    before={k:list(v) for k,v in groups.items()}
    with pytest.raises(UnsupportedAPI,match='sequence index collides'):call(model,uc,b'kernel32.dll')
    assert groups==before and model.handler.load_library_counter['kernel32.dll']==0


@pytest.mark.parametrize('name',[b'unknown.dll',b'C:\\Other\\kernel32.dll',b'kernel32.',b'C:/Windows/System32/kernel32.dll'])
def test_unmodeled_names_do_not_alias_a_known_guest_image(name):
    model,uc,legacy,_=fixture()
    assert call(model,uc,name)[0]==0 and legacy==[] and model.last_error==126
    assert model.handler.module_handles=={}


@pytest.mark.parametrize('name',[b'user32.dll',b'USER32',b'C:\\Windows\\System32\\user32.dll'])
def test_abstract_import_token_is_never_returned_as_a_mapped_hmodule(name):
    model,uc,legacy,stops=fixture()
    model.handler.module_handles[0x400000]='user32.dll'
    model.handler.load_library_counter['user32.dll']=0
    with pytest.raises(UnsupportedAPI,match='user32.dll.*no mapped PE image'):call(model,uc,name)
    assert stops==[True] and legacy==[]
    assert model.handler.module_handles=={0x400000:'user32.dll'}


def test_loaded_core_module_wrong_path_does_not_alias_an_abstract_backend_name():
    model,uc,legacy,_=fixture();call(model,uc,b'kernel32.dll')
    assert call(model,uc,b'C:\\Other\\kernel32.dll')[0]==0 and model.last_error==126
    assert legacy==[]


def test_abstract_module_names_without_extensions_are_still_recognized():
    model,uc,_,_=fixture();model.handler.load_library_counter['USER32']=0
    with pytest.raises(UnsupportedAPI,match='user32.dll.*no mapped PE image'):call(model,uc,b'user32.dll')


def test_unmapped_or_conflicting_recorded_module_fails_instead_of_inventing_a_handle():
    model,uc,_,stops=fixture();uc.regions=[r for r in uc.regions if r[0]!=0x755d0000]
    with pytest.raises(UnsupportedAPI,match='no longer mapped'):call(model,uc,b'kernel32.dll')
    assert stops==[True] and model.handler.module_handles=={}
    model,uc,_,_=fixture();model.handler.module_handles[0x755d0000]='different.dll'
    with pytest.raises(UnsupportedAPI,match='collides'):call(model,uc,b'kernel32.dll')
    assert model.handler.module_handles[0x755d0000]=='different.dll'


def test_guest_header_modification_does_not_change_loaded_module_identity():
    model,uc,_,_=fixture();uc.mem_write(0x755d0000,b'XX')
    assert call(model,uc,b'kernel32.dll')[0]==0x755d0000


def test_module_diagnostics_are_bounded_and_survive_progress_export(tmp_path):
    from unpacker.unpackers._unipacker_shared import _write_engine_progress
    from unpacker.backend_worker import _progress_metadata
    model,uc,_,_=fixture()
    for _ in range(40):call(model,uc,b'kernel32.dll')
    facts=model.modules.facts()
    assert facts['resolved_queries']==40 and len(facts['resolutions'])==16
    engine=model.engine;engine._unpacker_module_model=model.modules
    engine.apicall_counter={'GetModuleHandleA':40};engine.sections_executed={}
    engine._unpacker_instructions=65536
    _write_engine_progress(engine,tmp_path/'.emulation-progress.json')
    assert _progress_metadata(tmp_path)['worker_progress']['module_handles']==facts
