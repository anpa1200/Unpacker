"""Benign x86 reference fixtures. Expected ABI follows pinned Wine/Microsoft.

Only Unicorn runs these small synthesized programs. This is not a fresh native
Windows oracle run, and no packed specimen or native callback is involved.
"""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EIP,UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_EFLAGS
from unpacker.stack_exceptions import StackExceptionDispatcher
from unpacker.guest_seh import UnsupportedDispatch,UnhandledGuestException


def unicorn_invalid_flags():
    from unicorn import UC_HOOK_MEM_READ_UNMAPPED,UC_HOOK_MEM_WRITE_UNMAPPED
    return UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED


def fixture(program=b'\xf1\xbb\x78\x56\x34\x12\x90',handlers=None,access_violations=False):
    uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0,0x100000,7);uc.mem_map(0x200000,4096,3);uc.mem_map(0x401000,0x5000,7)
    uc.windows_tib=0x200000;uc.mem_write(0x401000,program)
    handlers=handlers or {0x402000:bytes.fromhex('31c0c3')}
    for address,code in handlers.items():uc.mem_write(address,code)
    uc.mem_write(0x7fff0,struct.pack('<II',0xffffffff,0x402000));uc.mem_write(0x200000,struct.pack('<I',0x7fff0))
    uc.reg_write(UC_X86_REG_ESP,0x7fff0);uc.reg_write(UC_X86_REG_EAX,0x10203040)
    engine=N(uc=uc,STACK_ADDR=0,STACK_SIZE=0x100000,TEB_BASE=0x200000,stop=uc.emu_stop,
             apicall_handler=N(hooks={},apicall=lambda *a:(None,a[3])))
    d=StackExceptionDispatcher(engine,access_violations=access_violations);captures=[]
    if access_violations:
        def invalid(uc,access,address,size,value,user):
            engine._unpacker_memory_fault={'access':access,'address':address,'size':size};return False
        uc.hook_add(unicorn_invalid_flags(),invalid)
    def code(uc,address,size,user):
        engine._unpacker_last_address=address
        try:
            if d.observe_instruction(address,size):return
            if address in handlers and d.levels:
                level=d.levels[-1];record=struct.unpack('<5I',uc.mem_read(level['record_address'],20))
                captures.append({'record':record,'context_address':level['context_address'],'depth':len(d.levels),
                 'eip':struct.unpack('<I',uc.mem_read(level['context_address']+0xb8,4))[0],
                 'flags':struct.unpack('<I',uc.mem_read(level['context_address']+0xc0,4))[0],
                 'debug':{n:struct.unpack('<I',uc.mem_read(level['context_address']+o,4))[0] for n,o in d.DEBUG_REGISTERS.items()},
                 'increment_before_handler':struct.unpack('<I',uc.mem_read(0x404004,4))[0]})
            if address in engine.apicall_handler.hooks:
                _,esp=engine.apicall_handler.apicall(address,engine.apicall_handler.hooks[address],uc,uc.reg_read(UC_X86_REG_ESP),False)
                uc.reg_write(UC_X86_REG_ESP,esp)
        except UnsupportedDispatch:uc.emu_stop()
    def memory(uc,access,address,size,value,user):
        try:d.check_context_access(address,size,writing=access==UC_MEM_WRITE)
        except UnsupportedDispatch:uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
    return engine,d,0x401000+len(program),captures


def execute(engine,d,end):
    start=0x401000
    for _ in range(256):
        error=None
        try:engine.uc.emu_start(start,end,timeout=100000,count=1000)
        except UcError as exc:error=exc;d.capture_cpu_error(exc)
        if d.unsupported:return
        resume=d.take_resume()
        if resume is not None:start=resume;continue
        handler=d.arm()
        if handler is not None:start=handler;continue
        if error is not None:raise error
        return
    raise AssertionError('Bounded synthetic runner exhausted')


def word(engine,address):return struct.unpack('<I',engine.uc.mem_read(address,4))[0]


def test_single_icebp_handler_and_guard_restore_the_original_chain():
    e,d,end,c=fixture();execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and e.uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert word(e,0x200000)==0x7fff0 and not d.active
    assert c[0]['record']==(0x80000004,0,0,0x401001,0)
    assert d.events[0]['status']=='continue_execution'


def test_continue_search_preserves_one_exception_context_and_calls_outer_frame():
    first=bytes.fromhex('8b44240cc780b000000044332211b801000000c3')
    second=bytes.fromhex('31c0c3')
    e,d,end,c=fixture(handlers={0x402000:first,0x403000:second})
    e.uc.mem_write(0x7fff0,struct.pack('<II',0x7fff8,0x402000));e.uc.mem_write(0x7fff8,struct.pack('<II',0xffffffff,0x403000))
    execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and e.uc.reg_read(UC_X86_REG_EAX)==0x11223344
    assert len(c)==2 and c[0]['context_address']==c[1]['context_address']
    assert [h['disposition'] for h in d.events[0]['handlers']]==[1,0]
    assert word(e,0x200000)==0x7fff0


def test_nested_handler_gets_independent_context_and_returns_to_parent():
    # Register a child handler below the dispatch guard, INT3, unregister it.
    outer=bytes.fromhex('680030400064ff350000000064892500000000cc648f050000000083c40431c0c3')
    child=bytes.fromhex('8b44240c8380b80000000131c0c3')
    e,d,end,c=fixture(handlers={0x402000:outer,0x403000:child});execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and not d.active and len(d.events)==2
    assert [x['depth'] for x in c]==[1,2] and len({x['context_address'] for x in c})==2
    assert all(x['record'][2]==0 for x in c)  # Hardware records do not invent a parent pointer.
    assert all(x['status']=='continue_execution' for x in d.events)
    assert word(e,0x200000)==0x7fff0


def test_fault_inside_handler_crosses_the_dispatcher_guard_with_nested_flag():
    # Record flags identify second entry. Its handler skips the nested INT3.
    outer=bytes.fromhex('8b442404f7400410000000750531c0ccc3908b44240c8380b80000000131c0c3')
    e,d,end,c=fixture(handlers={0x402000:outer});execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and len(c)==2 and not d.active
    assert c[0]['record'][1]==0 and c[1]['record'][1]&0x10
    assert any(h.get('dispatcher_guard') and h['disposition']==2 for h in d.events[1]['handlers'])


def test_handler_can_leave_nonlocally_only_after_detaching_its_stack_registration():
    # Handler explicitly moves to its frame, pops Prev/Handler and jumps to guest code.
    handler=bytes.fromhex('8b642408648f050000000058e9f10fffff')
    # Patch relative JMP to the instruction following the F1, not a host-selected continuation.
    handler=handler[:-4]+struct.pack('<i',0x401001-(0x402000+len(handler)))
    e,d,end,c=fixture(handlers={0x402000:handler});execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and not d.active
    assert d.events[0]['status']=='guest_nonlocal_exit' and word(e,0x200000)==0xffffffff
    assert e.uc.reg_read(UC_X86_REG_EAX)==0x402000  # Guest changes survive; CONTEXT wasn't silently restored.


def test_nonlocal_stack_change_without_detaching_guard_never_marks_handler_complete():
    handler=bytes.fromhex('8b642408e9')+struct.pack('<i',0x401001-(0x402000+9))
    e,d,end,_=fixture(handlers={0x402000:handler});execute(e,d,end)
    assert d.active and d.events[0]['status']=='handler_pending'


def test_native_reference_single_step_sequence_has_three_events_and_cleared_context_tf():
    # Same transitions as Wine single_stepcode, manually synthesized here.
    program=bytes.fromhex('9c580d00010000509d3500010000509d90')
    # Count handler calls in benign data. Re-enable TF only for the first two.
    handler=bytes.fromhex('ff0500404000833d0040400003730e8b44240c8188c00000000001000031c0c3')
    e,d,end,c=fixture(program,handlers={0x402000:handler});execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and len(c)==3 and word(e,0x404000)==3
    assert all(x['record'][0]==0x80000004 and not x['flags']&0x100 for x in c)
    assert [x['eip'] for x in c]==[0x40100e,0x40100f,0x401010]
    assert not d.unsupported and not e.uc.reg_read(UC_X86_REG_EFLAGS)&0x100


@pytest.mark.parametrize('program',[bytes.fromhex('cd0190'),bytes.fromhex('cd0390'),bytes.fromhex('cd0490')])
def test_other_interrupts_are_not_misclassified_as_tf_or_short_int3(program):
    e,d,end,_=fixture(program);execute(e,d,end)
    assert d.unsupported and not d.events


def test_event_budget_still_stops_a_handler_that_never_advances_int3():
    e,d,end,_=fixture(b'\xcc\x90');d.MAX_FAULTS=8
    with pytest.raises(UnsupportedDispatch,match='event budget'):execute(e,d,end)
    assert len(d.events)==8 and len(d.slots)==1


def test_search_to_chain_end_is_unhandled_not_success():
    e,d,end,_=fixture(handlers={0x402000:bytes.fromhex('b801000000c3')})
    with pytest.raises(UnhandledGuestException,match='No stack handler'):execute(e,d,end)


def test_invalid_or_cyclic_registration_is_rejected_before_handler_execution():
    e,d,end,c=fixture();e.uc.mem_write(0x7fff0,struct.pack('<II',0x7fff0,0x402000))
    with pytest.raises(UnsupportedDispatch,match='chain order'):execute(e,d,end)
    assert not c


def test_uninitialized_dispatcher_output_cannot_supply_nested_frame():
    e,d,end,_=fixture(handlers={0x402000:bytes.fromhex('b802000000c3')});execute(e,d,end)
    assert 'complete dispatcher output' in d.unsupported


def test_reading_uninitialized_dispatcher_output_is_explicitly_unsupported():
    e,d,end,_=fixture(handlers={0x402000:bytes.fromhex('8b4424108b0031c0c3')});execute(e,d,end)
    assert 'before guest initialization' in d.unsupported


def test_collided_unwind_is_not_invented_as_success():
    e,d,end,_=fixture(handlers={0x402000:bytes.fromhex('b803000000c3')});execute(e,d,end)
    assert 'Unwind/collided' in d.unsupported


def test_nested_profile_stops_at_its_depth_bound():
    # Every handler installs another registration before trapping.
    handler=bytes.fromhex('680020400064ff350000000064892500000000cc31c0c3')
    e,d,end,_=fixture(handlers={0x402000:handler});d.MAX_DEPTH=2
    with pytest.raises(UnsupportedDispatch,match='nesting budget'):execute(e,d,end)
    assert len(d.levels)==2 and len(d.slots)==2


def test_modified_guard_frame_is_not_treated_as_trusted_dispatcher_behavior():
    # FS:[0] is the live dispatcher guard; corrupt its handler pointer.
    handler=bytes.fromhex('64a100000000c740040000000031c0c3')
    e,d,end,_=fixture(handlers={0x402000:handler});execute(e,d,end)
    assert 'changed a live dispatcher guard' in d.unsupported


def test_nested_disposition_needs_a_valid_written_frame_in_the_current_chain():
    # Write outside-stack pointer to the actual output slot, return Nested.
    handler=bytes.fromhex('8b442410c70000304000b802000000c3')
    e,d,end,_=fixture(handlers={0x402000:handler});execute(e,d,end)
    assert 'outside its chain' in d.unsupported


def test_handler_debug_payload_access_remains_unsupported_with_nested_model():
    handler=bytes.fromhex('8b44240c8b401c31c0c3')
    e,d,end,_=fixture(handlers={0x402000:handler});execute(e,d,end)
    assert 'debug/floating-point' in d.unsupported


def execution_config_handler(target,control=1):
    # A real guest handler configures CONTEXT debug registers on its first call.
    config=bytes.fromhex('8b44240cc74004')+struct.pack('<I',target)+bytes.fromhex('c74018')+struct.pack('<I',control)
    return bytes.fromhex('ff0500404000833d004040000175')+bytes([len(config)])+config+bytes.fromhex('8b44240cc740140000000031c0c3')


def test_guest_execution_breakpoint_faults_before_instruction_and_rf_allows_one_retry():
    # Two visits to the same increment prove RF is consumed, not left forever.
    program=bytes.fromhex('b902000000f1ff0504404000e2f890')
    e,d,end,c=fixture(program,handlers={0x402000:execution_config_handler(0x401006)})
    execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and word(e,0x404004)==2 and word(e,0x404000)==3
    assert [x['kind'] for x in d.events]==['icebp','execution_breakpoint','execution_breakpoint']
    assert [x['record'][3] for x in c]==[0x401006,0x401006,0x401006]
    assert c[1]['flags']&0x10000 and c[2]['flags']&0x10000
    assert not e.uc.reg_read(UC_X86_REG_EFLAGS)&0x10000
    assert [x['increment_before_handler'] for x in c]==[0,0,1]
    assert all(x['debug']['DR6']&0xf==1 and x['debug']['DR0']==0x401006 for x in c[1:])


@pytest.mark.parametrize('control',[0x10001,0x30001,0x20001,0x40001])
def test_data_io_and_nonunit_execution_breakpoints_fail_before_claiming_support(control):
    e,d,end,_=fixture(handlers={0x402000:execution_config_handler(0x401001,control)})
    execute(e,d,end)
    assert 'Only one-byte execution breakpoints' in d.unsupported
    assert len(d.events)==1 and d.events[0]['status']=='handler_pending'


def test_general_detect_debug_control_is_explicitly_unsupported():
    e,d,end,_=fixture(handlers={0x402000:execution_config_handler(0x401001,0x2001)})
    execute(e,d,end)
    assert 'general-detect' in d.unsupported


@pytest.mark.parametrize('program,pc',[
    (bytes.fromhex('31db31d2b801000000f7f3bb7856341290'),0x401009),
    (bytes.fromhex('bb01000000ba0100000031c0f7f3bb7856341290'),0x40100c),
])
def test_divide_zero_and_quotient_overflow_use_cpu_fault_and_guest_continuation(program,pc):
    handler=bytes.fromhex('8b44240c8380b80000000231c0c3')
    e,d,end,c=fixture(program,handlers={0x402000:handler});execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and e.uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert c[0]['record']==(0xc0000094,0,0,pc,0) and c[0]['eip']==pc
    assert c[0]['flags']&0x10000 and d.events[0]['kind']=='divide_error'


def test_software_int_zero_is_not_misrepresented_as_cpu_division():
    e,d,end,_=fixture(bytes.fromhex('cd0090'));execute(e,d,end)
    assert 'DIV/IDIV' in d.unsupported and not d.events


def test_divide_error_without_registration_is_unhandled():
    e,d,end,_=fixture(bytes.fromhex('31db31d2f7f390'));e.uc.mem_write(0x200000,struct.pack('<I',0xffffffff))
    with pytest.raises(UnhandledGuestException,match='no registered'):execute(e,d,end)


def test_execution_breakpoint_preempts_resident_api_marker_side_effects():
    from unpacker.unpackers._unipacker_shared import _observed_engine
    e,d,end,_=fixture();calls=[]
    values=dict(d.debug_state);values.update(DR0=0x61001000,DR7=1);d._configure_debug(values)
    e.uc.mem_map(0x61001000,4096,5);e.uc.mem_write(0x61001000,b'\x90')
    class Base:
        def hook_code(self,*args):calls.append('api-side-effect')
    observed=_observed_engine(Base,False,None)();observed.__dict__.update(e.__dict__)
    observed._unpacker_seh_dispatcher=d;observed.apicall_counter={};observed.sections_executed={}
    observed.sample=N(unpacker=N(get_section=lambda address:'external'))
    observed._unpacker_desktop_modules=N(is_dispatch_site=lambda *args:calls.append('marker') or True)
    observed.hook_code(e.uc,0x61001000,1,None)
    assert not calls and d.software_pending['kind']=='execution_breakpoint'


@pytest.mark.parametrize('opcode',[b'\x8d\xc0',b'\x0f\x0b'])
def test_only_proven_invalid_encodings_are_delivered_as_illegal_instruction(opcode):
    handler=bytes.fromhex('8b44240c8380b80000000231c0c3')
    program=opcode+bytes.fromhex('bb7856341290')
    e,d,end,c=fixture(program,handlers={0x402000:handler});execute(e,d,end)
    assert e.uc.reg_read(UC_X86_REG_EIP)==end and e.uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert c[0]['record']==(0xc000001d,0,0,0x401000,0)
    assert c[0]['eip']==0x401000 and d.events[0]['kind']=='illegal_instruction'


def test_unsupported_backend_error_is_not_automatically_fabricated_as_architectural_ud():
    from unicorn import UC_ERR_INSN_INVALID
    e,d,end,_=fixture(b'\x90\x90');e.uc.reg_write(UC_X86_REG_EIP,0x401000)
    assert not d.capture_cpu_error(UcError(UC_ERR_INSN_INVALID)) and not d.events


def test_extended_event_budget_handles_nine_independent_icebp_faults_without_more_workspace():
    e,d,end,c=fixture(b'\xf1'*9+b'\x90');execute(e,d,end)
    assert len(d.events)==9 and len(d.slots)==1 and e.uc.reg_read(UC_X86_REG_EIP)==end
    assert d.facts()['allocated_workspace_bytes']==8192 and d.MAX_DEPTH==8 and d.MAX_FAULTS==64


def test_default_extended_budget_is_finite_and_keeps_workspace_bounded():
    e,d,end,_=fixture(b'\xcc\x90')
    with pytest.raises(UnsupportedDispatch,match='event budget'):execute(e,d,end)
    assert len(d.events)==64 and len(d.slots)==1 and d.facts()['allocated_workspace_bytes']==8192


@pytest.mark.parametrize('opcode',[b'\xf1',b'\x0f\x0b'])
def test_short_fault_decoder_does_not_require_unmapped_bytes_after_instruction(opcode):
    from unicorn import UC_ERR_INSN_INVALID
    e,d,end,_=fixture();address=0x406000-len(opcode)
    e.uc.mem_write(address,opcode);e.uc.reg_write(UC_X86_REG_EIP,address)
    assert d.capture_cpu_error(UcError(UC_ERR_INSN_INVALID))
    assert d.software_pending['origin']==address and not d.unsupported


@pytest.mark.parametrize('instruction',[bytes.fromhex('f7f3'),bytes.fromhex('66f7f3'),bytes.fromhex('f7fb'),bytes.fromhex('66f7fb')])
def test_repeated_independent_divides_do_not_inherit_backend_double_fault_state(instruction):
    handler=bytes.fromhex('8b44240c8380b8000000')+bytes([len(instruction)])+bytes.fromhex('31c0c3')
    program=bytes.fromhex('31db31d2')+instruction+instruction+bytes.fromhex('bb7856341290')
    e,d,end,c=fixture(program,handlers={0x402000:handler});execute(e,d,end)
    assert not d.unsupported and len(d.events)==2
    assert all(x['kind']=='divide_error' and x['status']=='continue_execution' for x in d.events)
    assert e.uc.reg_read(UC_X86_REG_EBX)==0x12345678 and e.uc.reg_read(UC_X86_REG_EIP)==end


def test_real_double_fault_vector_is_never_relabelled_as_divide():
    e,d,end,c=fixture(bytes.fromhex('31dbf7f390'))
    e.uc.reg_write(UC_X86_REG_EIP,0x401002);d.observe_instruction(0x401002,2)
    d._interrupt(e.uc,8,None)
    assert 'outside the bounded' in d.unsupported and not d.events and d.software_pending is None


@pytest.mark.parametrize('opcode,permissions,operation',[(b'\xa3',1,1),(b'\xa1',0,0)])
def test_real_protected_memory_fault_is_delivered_without_relaxing_permissions(opcode,permissions,operation):
    target=0x405000;handler=bytes.fromhex('8b44240c8380b80000000531c0c3')
    program=opcode+struct.pack('<I',target)+bytes.fromhex('bb7856341290')
    e,d,end,c=fixture(program,handlers={0x402000:handler},access_violations=True)
    e.uc.mem_protect(target,4096,permissions);execute(e,d,end)
    assert not d.unsupported and e.uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert c[0]['record']==(0xc0000005,0,0,0x401000,2)
    assert struct.unpack('<2I',e.uc.mem_read(d.record_address+20,8))==(operation,target)
    assert c[0]['flags']&0x10000 and d.events[0]['kind']=='access_violation'
    assert next(p for lo,hi,p in e.uc.mem_regions() if lo<=target<=hi)==permissions


def test_repeated_write_faults_do_not_write_or_skip_without_guest_context_change():
    target=0x405000;handler=bytes.fromhex('8b44240c8380b80000000531c0c3')
    program=(b'\xa3'+struct.pack('<I',target))*2+b'\x90'
    e,d,end,c=fixture(program,handlers={0x402000:handler},access_violations=True)
    e.uc.mem_protect(target,4096,1);execute(e,d,end)
    assert len(d.events)==2 and all(x['status']=='continue_execution' for x in d.events)
    assert e.uc.mem_read(target,4)==bytes(4) and e.uc.reg_read(UC_X86_REG_EIP)==end


def test_unmapped_read_is_reported_and_memory_stays_unmapped_after_guest_skip():
    target=0x900000;handler=bytes.fromhex('8b44240c8380b80000000531c0c3')
    e,d,end,c=fixture(b'\xa1'+struct.pack('<I',target)+b'\x90',handlers={0x402000:handler},access_violations=True)
    execute(e,d,end)
    assert d.events[0]['fault_operation']==0 and d.events[0]['fault_address']==target
    with pytest.raises(UcError):e.uc.mem_read(target,1)


def test_unregistered_access_violation_is_unhandled_not_success():
    e,d,end,c=fixture(b'\xa1'+struct.pack('<I',0x900000),access_violations=True)
    e.uc.mem_write(0x200000,struct.pack('<I',0xffffffff))
    with pytest.raises(UnhandledGuestException,match='no registered'):execute(e,d,end)


def test_default_software_only_profile_does_not_swallow_recorded_memory_fault():
    from unicorn import UC_MEM_READ_UNMAPPED
    e,d,end,c=fixture();e._unpacker_memory_fault={'access':UC_MEM_READ_UNMAPPED,'address':0x900000,'size':4}
    assert d.arm() is None and not d.events


@pytest.mark.parametrize('name,generic,cap,scope',[('PEtite',False,8,'PEtite'),('unknown',True,64,'generic_PE32')])
def test_factory_selects_bounded_av_profile_without_increasing_existing_caps(name,generic,cap,scope):
    from unpacker.unpackers._unipacker_shared import _exception_dispatcher
    e,old,end,c=fixture();d=_exception_dispatcher(e,name,generic)
    assert d.access_violations and d.MAX_FAULTS==cap and d.MAX_DEPTH==8 and d.facts()['scope']==scope


def test_arming_av_consumes_fault_before_handler_can_exit_nonlocally():
    e,d,end,c=fixture(b'\xa1'+struct.pack('<I',0x900000),access_violations=True)
    with pytest.raises(UcError):e.uc.emu_start(0x401000,end,count=4)
    assert e._unpacker_memory_fault is not None
    assert d.arm()==0x402000 and e._unpacker_memory_fault is None


def test_native_snapshot_fault_is_not_fictionally_delivered_to_guest_handler():
    e,d,end,c=fixture(b'\xa1'+struct.pack('<I',0x900000),access_violations=True)
    e.sample=N(BASE_ADDR=0x300000);e._unpacker_loader_lists={'module_images':[{'base':0x401000,'image_size':0x5000,'name':'kernel32.dll'}]}
    with pytest.raises(UnsupportedDispatch,match='native DLL'):execute(e,d,end)
    assert not d.events
