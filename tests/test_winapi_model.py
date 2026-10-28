"""Memory-only guest API tests; no guest path is opened on the host."""
import struct
from types import SimpleNamespace as N
import pytest
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI


class Memory:
    def __init__(self):self.data=bytearray(0x100000);self.unmapped=[]
    def mem_read(self,address,size):return self.data[address:address+size]
    def mem_write(self,address,value):self.data[address:address+len(value)]=value
    def mem_unmap(self,address,size):self.unmapped.append((address,size))


def fixture_model():
    memory=Memory();sample=N(BASE_ADDR=0x400000,allocated_chunks=[]);handler=N(alloc_sizes={})
    def alloc(log,size,uc):
        base=0x10000+len(handler.alloc_sizes)*0x10000;handler.alloc_sizes[base]=size;sample.allocated_chunks.append((base,base+size));return base
    handler.alloc=alloc;stops=[];engine=N(sample=sample,apicall_handler=handler,stop=lambda:stops.append(True))
    return SelfFileModel(engine,b'benign fixture',65536),memory,stops


def test_self_file_mapping_reads_only_supplied_specimen_bytes():
    model,uc,stops=fixture_model();model.module_name(uc,0,0x100,128)
    handle=model.open_self(uc,0x100,0x80000000,1,0,3,0,0)
    assert model.file_size(uc,handle,0)==14
    mapping=model.create_mapping(uc,handle,0,2,0,0,0);view=model.map_view(uc,mapping,4,0,0,0)
    assert uc.mem_read(view,14)==b'benign fixture'
    assert model.unmap_view(uc,view)==1 and uc.unmapped==[(view,4096)]
    assert not model.engine.sample.allocated_chunks
    assert model.close(uc,handle)==1 and model.close(uc,handle)==0


@pytest.mark.parametrize('path',[b'/etc/passwd',b'C:\\Users\\secret'])
def test_guest_paths_never_open_arbitrary_host_or_network_locations(path):
    model,uc,_=fixture_model();uc.mem_write(0x100,path+b'\0')
    assert model.open_self(uc,0x100,0,0,0,3,0,0)==0xffffffff and model.last_error==2


def test_network_file_namespace_stops_explicitly_without_a_host_fallback():
    model,uc,_=fixture_model();uc.mem_write(0x100,b'https://example.test\0')
    with pytest.raises(UnsupportedAPI,match='network'):
        model.open_self(uc,0x100,0,0,0,3,0,0)


def test_api_dispatch_obeys_stdcall_stack_and_stops_unknown_calls():
    model,uc,stops=fixture_model();model.install({});uc.mem_write(0x200,struct.pack('<II',0x12345678,9))
    value,esp=model.handler.apicall(0,'ExitProcess',uc,0x200,False)
    assert value==0 and esp==0x204 and uc.mem_read(esp,4)==struct.pack('<I',0x12345678) and stops==[True]
    with pytest.raises(UnsupportedAPI):model.handler.apicall(0,'UnknownAPI',uc,0x200,False)
    assert model.unsupported[-1]['name']=='UnknownAPI'


def test_unsupported_api_preserves_bounded_untyped_stack_words():
    model,uc,stops=fixture_model();model.install({})
    uc.mem_write(0x200,struct.pack('<8I',0x12345678,11,22,33,44,55,66,77))
    with pytest.raises(UnsupportedAPI):model.handler.apicall(0,'MissingAPI',uc,0x200,False)
    evidence=model.unsupported[-1]['call']
    assert evidence=={'name':'MissingAPI','stack_words':[11,22,33,44,55,66],'signature':'unknown'}
    assert stops==[True] and model.current_call is None


def test_unreadable_unknown_api_stack_still_reports_original_unsupported_api():
    model,uc,stops=fixture_model();model.install({})
    with pytest.raises(UnsupportedAPI):model.handler.apicall(0,'MissingAPI',uc,0x200000,False)
    assert model.unsupported[-1]['call']['stack_words']==[] and stops==[True]


def test_mapping_rejects_size_overflow_shared_views_and_writes():
    model,uc,_=fixture_model();model.module_name(uc,0,0x100,128)
    with pytest.raises(UnsupportedAPI):model.open_self(uc,0x100,0x40000000,0,0,3,0,0)
    handle=model.open_self(uc,0x100,0x80000000,0,0,3,0,0)
    with pytest.raises(UnsupportedAPI):model.create_mapping(uc,handle,0,2,1,0,0)
    mapping=model.create_mapping(uc,handle,0,2,0,0,0)
    with pytest.raises(UnsupportedAPI):model.map_view(uc,mapping,4,0,0,100000)
    model.map_view(uc,mapping,4,0,0,0)
    with pytest.raises(UnsupportedAPI):model.map_view(uc,mapping,4,0,0,0)


def test_message_choices_and_cache_approximation_are_explicit():
    model,uc,_=fixture_model()
    assert model.message(uc,0,0,0,4)==7
    assert model.events[-1]=={'operation':'MessageBoxA','response':7}
    assert model.flush(uc,0xffffffff,0,0)==1 and model.warnings


def test_guest_failure_message_and_exit_code_are_preserved_without_host_ui():
    model,uc,stops=fixture_model()
    uc.mem_write(0x100,b'Corrupt Data!\0');uc.mem_write(0x200,b'ERROR!\0')
    assert model.message(uc,0,0x100,0x200,0x10)==1
    assert model.last_message['text']=={'value':'Corrupt Data!','truncated':False}
    assert model.last_message['title']['value']=='ERROR!'
    model.exit(uc,0xffffffff)
    assert model.guest_exit_code==0xffffffff and stops==[True]


def test_guest_message_diagnostics_are_bounded_and_handle_unreadable_memory():
    model,uc,_=fixture_model();uc.mem_write(0x100,b'x'*300)
    model.message(uc,0,0x100,0x200000,0)
    assert model.last_message['text']=={'value':'x'*256,'truncated':True}
    assert model.last_message['title']=={'capture':'unreadable'}


def test_guest_wide_message_diagnostics_decode_utf16_without_host_calls():
    model,uc,_=fixture_model();uc.mem_write(0x100,'Guest\u03b1\0'.encode('utf-16le'))
    model.message(uc,0,0x100,0,0,True)
    assert model.last_message['text']=={'value':'Guest\u03b1','truncated':False}


def test_null_module_handle_refers_to_actual_image_without_allocating_copy():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x200,struct.pack('<II',0x12345678,0))
    value,esp=model.handler.apicall(0,'GetModuleHandleA',uc,0x200,False)
    assert value==0x400000 and esp==0x204 and not model.handler.alloc_sizes


def test_process_version_comes_from_input_subsystem_header_not_os_profile():
    model,uc,_=fixture_model();model.engine.sample.opt_header=N(MajorSubsystemVersion=4,MinorSubsystemVersion=7)
    model.handler.processid=1234
    assert model.process_version(uc,0)==0x00040007
    assert model.process_version(uc,1234)==0x00040007
    with pytest.raises(UnsupportedAPI,match='current emulated process'):model.process_version(uc,4321)


def test_system_metrics_use_explicit_guest_icon_profile_and_reject_unknown_metrics():
    model,uc,_=fixture_model()
    assert model.system_metrics(uc,11)==32 and model.system_metrics(uc,12)==32
    assert model.system_metrics(uc,2)==17 and model.system_metrics(uc,3)==17
    assert model.events[-1]['profile']=='guest_96dpi_basic_metrics'
    assert model.system_metrics(uc,0)==1920 and model.system_metrics(uc,1)==1080
    with pytest.raises(UnsupportedAPI,match='outside the fixed guest desktop profile'):model.system_metrics(uc,999)


@pytest.mark.parametrize('major,minor',[(None,0),(-1,0),(65536,0),(4,65536)])
def test_invalid_process_version_metadata_stops_explicitly(major,minor):
    model,uc,_=fixture_model();model.engine.sample.opt_header=N(MajorSubsystemVersion=major,MinorSubsystemVersion=minor)
    with pytest.raises(UnsupportedAPI,match='subsystem version'):model.process_version(uc,0)


def test_callback_exception_is_stopped_instead_of_swallowed_by_ctypes(tmp_path):
    from unpacker.unpackers._unipacker_shared import _observed_engine
    stopped=[]
    class Engine:
        def hook_code(self,*args):raise UnsupportedAPI('fixture unsupported API')
        def stop(self):stopped.append(True)
    observed=_observed_engine(Engine,False,tmp_path/'progress')()
    observed.hook_code(None,0x401000,1,None)
    assert stopped==[True] and 'UnsupportedAPI' in observed._unpacker_callback_error


def test_fixed_global_alloc_free_preserves_windows_return_contract_and_budget():
    model,uc,_=fixture_model();address=model.global_alloc(uc,0x40,12)
    assert uc.mem_read(address,12)==bytes(12) and model.global_free(uc,address)==0
    assert model.global_free(uc,address)==address
    with pytest.raises(UnsupportedAPI):model.global_alloc(uc,0x80000000,12)
    with pytest.raises(UnsupportedAPI):model.global_alloc(uc,0,model.limit+1)


def test_tick_count_tracks_virtual_process_uptime_and_wraps():
    model,uc,_=fixture_model();model.boot_time=0;model.clock=lambda:123.5
    assert model.tick_count(uc)==123500
    model.clock=lambda:(2**32+1024)/1000
    assert model.tick_count(uc)==1024


def test_version_info_uses_explicit_profile_and_checks_structure_size():
    model,uc,_=fixture_model();uc.mem_write(0x200,struct.pack('<I',156))
    assert model.version_info(uc,0x200)==1
    assert struct.unpack('<IIIII',uc.mem_read(0x200,20))==(156,6,1,7601,2)
    assert model.events[-1]['profile'].startswith('Windows 7')
    uc.mem_write(0x200,struct.pack('<I',200))
    with pytest.raises(UnsupportedAPI):model.version_info(uc,0x200)


def test_tls_slots_are_initialized_bounded_mirrored_and_have_error_semantics():
    model,uc,_=fixture_model();model.engine.TEB_BASE=0x2000
    index=model.tls_alloc(uc);assert index==0 and model.tls_get(uc,index)==0 and model.last_error==0
    assert model.tls_set(uc,index,0x12345678)==1 and uc.mem_read(0x2e10,4)==struct.pack('<I',0x12345678)
    assert model.tls_get(uc,index)==0x12345678 and model.tls_free(uc,index)==1
    assert model.tls_get(uc,index)==0 and model.last_error==87
    for _ in range(64):assert model.tls_alloc(uc)!=0xffffffff
    assert model.tls_alloc(uc)==0xffffffff


def test_single_thread_critical_sections_require_initialization_and_track_recursion():
    model,uc,_=fixture_model()
    with pytest.raises(UnsupportedAPI):model.critical_enter(uc,0x200)
    model.critical_init(uc,0x200);model.critical_enter(uc,0x200);model.critical_enter(uc,0x200)
    assert model.critical[0x200]==2
    with pytest.raises(UnsupportedAPI):model.critical_delete(uc,0x200)
    model.critical_leave(uc,0x200);model.critical_leave(uc,0x200);model.critical_delete(uc,0x200)
    assert 0x200 not in model.critical
    model.startup_info(uc,0x300);assert uc.mem_read(0x300,68)==struct.pack('<I',68)+bytes(64)


def test_heap_allocations_are_owned_bounded_and_zero_initialized():
    model,uc,_=fixture_model();model.handler.heaps={17:(0,1024)}
    address=model.heap_alloc(uc,17,8,16)
    assert model.heap_size(uc,17,0,address)==16 and uc.mem_read(address,16)==bytes(16)
    assert model.heap_alloc(uc,17,0,2048)==0
    assert model.heap_free(uc,18,0,address)==0 and model.heap_free(uc,17,0,address)==1
    with pytest.raises(UnsupportedAPI):model.heap_alloc(uc,18,0,4)


def test_single_thread_heap_no_serialize_is_consistent_across_allocation_size_free():
    model,uc,_=fixture_model();model.handler.heaps={17:(0,1024)}
    address=model.heap_alloc(uc,17,9,16)
    assert model.heap_size(uc,17,1,address)==16
    assert model.heap_size(uc,17,2,address)==0xffffffff
    assert model.heap_free(uc,17,2,address)==0 and address in model.heap_allocations
    assert model.heap_free(uc,17,1,address)==1 and address not in model.heap_allocations


def test_missing_standard_handles_are_virtual_not_host_console_handles():
    model,uc,_=fixture_model()
    assert model.standard_handle(uc,0xfffffff5)==0 and model.file_type(uc,0)==0 and model.last_error==6
    assert model.standard_handle(uc,123)==0xffffffff and model.last_error==87


def test_empty_crt_initializer_tables_use_cdecl_and_never_skip_guest_callbacks():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x200,struct.pack('<III',0x12345678,0x300,0x310))
    value,esp=model.handler.apicall(0,'_initterm',uc,0x200,False)
    assert value is None and esp==0x200
    value,esp=model.handler.apicall(0,'_initterm_e',uc,0x200,False)
    assert value==0 and esp==0x200


def test_process_heap_is_stable_supports_zero_bytes_and_cannot_be_destroyed():
    model,uc,_=fixture_model();model.handler.heaps={};model.handler.next_heap_handle=17
    heap=model.process_heap(uc);assert heap==17 and model.process_heap(uc)==heap
    address=model.heap_alloc(uc,heap,8,0)
    assert address and model.heap_size(uc,heap,0,address)==0
    assert model.heap_destroy(uc,heap)==0 and heap in model.handler.heaps
    assert model.heap_free(uc,heap,0,address)==1
    model.handler.heaps[18]=(0,0);owned=model.heap_alloc(uc,18,0,16)
    assert model.heap_destroy(uc,18)==1 and owned not in model.heap_allocations and 18 not in model.handler.heaps
    assert model.handle_count(uc,20)==20 and not model.handles


def test_crt_cells_are_per_process_stable_mutable_and_cdecl():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x200,struct.pack('<II',0x12345678,2))
    value,esp=model.handler.apicall(0,'__set_app_type',uc,0x200,False)
    assert value is None and esp==0x200 and model.application_type==2
    address,esp=model.handler.apicall(0,'__p__fmode',uc,0x200,False)
    assert esp==0x200 and uc.mem_read(address,4)==struct.pack('<I',0x4000)
    uc.mem_write(address,struct.pack('<I',0x8000))
    assert model.handler.apicall(0,'__p__fmode',uc,0x200,False)[0]==address
    assert uc.mem_read(address,4)==struct.pack('<I',0x8000)
    assert model.codepage_info(uc,0,0x300)==1 and uc.mem_read(0x300,20)==struct.pack('<I',1)+b'?\0'+bytes(14)
    assert model.codepage_info(uc,932,0x300)==0 and model.last_error==87


def test_exception_filter_registration_returns_previous_and_does_not_execute_it():
    model,uc,stops=fixture_model()
    assert model.set_exception_filter(uc,0x401000)==0
    assert model.set_exception_filter(uc,0x402000)==0x401000 and model.exception_filter==0x402000
    assert not stops


def test_movable_global_handles_lock_unlock_free_and_ignore_obsolete_share_flag():
    model,uc,_=fixture_model();handle=model.global_alloc(uc,0x2042,256)
    assert handle not in model.globals and model.global_size(uc,handle)==256
    address=model.global_lock(uc,handle)
    assert address in model.globals and uc.mem_read(address,256)==bytes(256)
    assert model.global_lock(uc,handle)==address and model.global_flags(uc,handle)==2
    assert model.close(uc,handle)==0 and handle in model.handles
    assert model.global_unlock(uc,handle)==1
    assert model.global_unlock(uc,handle)==0 and model.last_error==0
    assert model.global_unlock(uc,handle)==0 and model.last_error==158
    assert model.global_free(uc,handle)==0 and address not in model.globals and handle not in model.handles
    discarded=model.global_alloc(uc,2,0)
    assert model.global_flags(uc,discarded)==0x4000 and model.global_lock(uc,discarded)==0
    assert model.global_size(uc,discarded)==0 and model.global_free(uc,discarded)==0


def test_wide_message_box_keeps_stack_and_declares_noninteractive_choice():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x200,struct.pack('<5I',0x12345678,0,0,0,4))
    value,esp=model.handler.apicall(0,'MessageBoxW',uc,0x200,False)
    assert value==7 and esp==0x210
    assert model.events[-1]=={'operation':'MessageBoxW','response':7}
    assert 'noninteractive' in model.warnings[-1]
    assert model.message(uc,0,0,0,2)==3


def test_current_process_id_uses_existing_guest_identity_not_host_pid():
    model,uc,_=fixture_model();model.handler.processid=0x1234;model.install({})
    uc.mem_write(0x200,struct.pack('<I',0x12345678))
    value,esp=model.handler.apicall(0,'GetCurrentProcessId',uc,0x200,False)
    assert value==0x1234 and esp==0x200


@pytest.mark.parametrize('value',[None,0,-1,0x100000000,True])
def test_invalid_or_missing_guest_process_id_never_invents_one(value):
    model,uc,_=fixture_model();model.handler.processid=value
    with pytest.raises(UnsupportedAPI,match='virtual process identity'):model.current_process_id(uc)


def test_open_current_guest_process_retains_rights_and_close_destroys_only_handle():
    m,u,_=fixture_model();m.handler.processid=1234
    h=m.open_current_process(u,0x001fffff,0,1234)
    assert m.handles[h]==('process',{'pid':1234,'access':0x001fffff,'inherited':False,'profile':'current_unprotected_guest_process'})
    assert m.close(u,h)==1 and h not in m.handles and m.handler.processid==1234
    assert m.close(u,h)==0 and m.last_error==6


@pytest.mark.parametrize('access,inherit,pid',[(0,1,1234),(0x02000000,0,1234),(0x80000000,0,1234),(0x200000,0,1234),(0x438,0,999)])
def test_undeclared_process_security_or_foreign_identity_cannot_get_fake_handle(access,inherit,pid):
    m,u,_=fixture_model();m.handler.processid=1234
    with pytest.raises(UnsupportedAPI):m.open_current_process(u,access,inherit,pid)
    assert not m.handles


def test_open_current_guest_process_obeys_stdcall_without_host_process_access():
    m,u,_=fixture_model();m.handler.processid=1234;m.install({})
    u.mem_write(0x200,struct.pack('<4I',0x12345678,0x438,0,1234))
    h,esp=m.handler.apicall(0,'OpenProcess',u,0x200,False)
    assert esp==0x20c and m.handles[h][1]['access']==0x438


def test_heap_termination_policy_is_process_wide_irreversible_and_stdcall():
    m,u,_=fixture_model();m.install({});u.mem_write(0x200,struct.pack('<5I',0x12345678,0,1,0,0))
    value,esp=m.handler.apicall(0,'HeapSetInformation',u,0x200,False)
    assert value==1 and esp==0x210 and m.heap_policy.enabled
    assert m.heap_policy.set_information(u,0,1,0,0)==1


@pytest.mark.parametrize('arguments',[(0,0,0,0),(0,3,0,0),(1,1,0,0),(0,1,0x100,0),(0,1,0,4)])
def test_unmodeled_heap_information_never_returns_success_or_disables_policy(arguments):
    m,u,_=fixture_model();m.heap_policy.set_information(u,0,1,0,0)
    with pytest.raises(UnsupportedAPI):m.heap_policy.set_information(u,*arguments)
    assert m.heap_policy.enabled


def test_enabled_heap_policy_terminates_only_on_recorded_double_free():
    from unpacker.heap_policy import GuestHeapCorruption
    m,u,stops=fixture_model();m.handler.heaps={};m.handler.next_heap_handle=1
    m.heap_policy.set_information(u,0,1,0,0);heap=m.process_heap(u);p=m.heap_alloc(u,heap,0,8)
    assert m.heap_free(u,heap,0,p)==1
    with pytest.raises(GuestHeapCorruption):m.heap_free(u,heap,0,p)
    assert m.guest_exit_code==0xc0000374 and stops and not m.unsupported


def test_unknown_corruption_sensitive_free_stops_instead_of_inventing_native_behavior():
    m,u,_=fixture_model();m.heap_policy.set_information(u,0,1,0,0)
    with pytest.raises(UnsupportedAPI,match='provenance'):m.heap_free(u,1,0,0x1234)
    assert m.guest_exit_code is None


def test_recent_free_tracking_is_bounded_and_address_reuse_removes_tombstone():
    m,u,_=fixture_model()
    for p in range(200):m.heap_policy.freed(1,p)
    assert len(m.heap_policy.recent_frees)==128
    m.heap_policy.allocated(1,199);assert (1,199) not in m.heap_policy.recent_frees
