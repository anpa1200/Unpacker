"""Tiny synthetic x86 programs; no specimens, native callbacks or nested emu_start.

Context EIP/record expectations follow pinned Wine's native-Windows regression
tests: short INT3 points at CC; ICEBP reports the following instruction.
"""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EIP,UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX
from unpacker.guest_seh import AccessViolationDispatcher,UnsupportedDispatch,UnhandledGuestException


def fixture(prefix,handler,registered=True,modeled_api=False):
    uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0,0x100000,7);uc.mem_map(0x200000,4096,3);uc.mem_map(0x401000,8192,7)
    program=prefix+bytes.fromhex('bb7856341290');uc.mem_write(0x401000,program);uc.mem_write(0x402000,handler)
    uc.mem_write(0x7fff8,struct.pack('<II',0xffffffff,0x402000))
    uc.mem_write(0x200000,struct.pack('<I',0x7fff8 if registered else 0xffffffff))
    uc.reg_write(UC_X86_REG_ESP,0x7fff8);uc.reg_write(UC_X86_REG_EAX,0x10203040);uc.reg_write(UC_X86_REG_ECX,0x55667788)
    engine=N(uc=uc,STACK_ADDR=0,STACK_SIZE=0x100000,TEB_BASE=0x200000,stop=uc.emu_stop,
             apicall_handler=N(hooks={},apicall=lambda *a:(None,a[3])))
    if modeled_api:
        from unpacker.winapi_model import SelfFileModel
        engine.model=SelfFileModel(engine,b'benign',32*1024*1024);engine.model.install({})
    dispatcher=AccessViolationDispatcher(engine,access_violations=False,software_traps=True,null_page_guard=False);captured=[]
    def code(uc,address,size,user):
        if address==0x402000:
            esp=uc.reg_read(UC_X86_REG_ESP);record,frame,context,extra=struct.unpack('<4I',uc.mem_read(esp+4,16))
            captured.append({'record':struct.unpack('<5I',uc.mem_read(record,20)),
                'eip':struct.unpack('<I',uc.mem_read(context+0xb8,4))[0], 'frame':frame,'extra':extra})
        if address in engine.apicall_handler.hooks:
            try:
                value,esp=engine.apicall_handler.apicall(address,engine.apicall_handler.hooks[address],uc,uc.reg_read(UC_X86_REG_ESP),False)
                uc.reg_write(UC_X86_REG_ESP,esp)
            except UnsupportedDispatch:pass
    def memory(uc,access,address,size,value,user):
        try:dispatcher.check_context_access(address,size)
        except UnsupportedDispatch:pass
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
    return engine,dispatcher,0x401000+len(program),captured


def execute(engine,dispatcher,end):
    start=0x401000
    for _ in range(32):
        error=None
        try:engine.uc.emu_start(start,end,timeout=100000,count=128)
        except UcError as exc:
            error=exc;dispatcher.capture_cpu_error(exc)
        if dispatcher.unsupported:return
        resume=dispatcher.take_resume()
        if resume is not None:start=resume;continue
        handler=dispatcher.arm()
        if handler is not None:start=handler;continue
        if error is not None:raise error
        return
    raise AssertionError('Synthetic software-trap execution exceeded bound')


@pytest.mark.parametrize('opcode,handler,code,eip',[
    (b'\xcc',bytes.fromhex('8b44240c8380b800000001b9efbeadde31c0c3'),0x80000003,0x401000),
    (b'\xf1',bytes.fromhex('b9efbeadde31c0c3'),0x80000004,0x401001),
])
def test_guest_handler_receives_native_compatible_record_and_context_and_resumes(opcode,handler,code,eip):
    engine,dispatcher,end,captured=fixture(opcode,handler);execute(engine,dispatcher,end)
    assert len(captured)==1 and captured[0]['record']==(code,0,0,eip,3 if opcode==b'\xcc' else 0)
    assert captured[0]['eip']==eip and captured[0]['frame']==0x7fff8
    assert engine.uc.reg_read(UC_X86_REG_EIP)==end and engine.uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert engine.uc.reg_read(UC_X86_REG_EAX)==0x10203040 and engine.uc.reg_read(UC_X86_REG_ECX)==0x55667788
    assert dispatcher.events[0]['status']=='continue_execution' and not dispatcher.unsupported
    # Adding this profile did not silently change the ordinary guest stack map.
    assert uc_read(engine,0,1)==b'\0' and not dispatcher.null_page_guard


def uc_read(engine,address,count):return bytes(engine.uc.mem_read(address,count))


@pytest.mark.parametrize('opcode',[b'\xcc',b'\xf1'])
def test_missing_registration_never_turns_exception_into_automatic_skip(opcode):
    engine,dispatcher,end,_=fixture(opcode,bytes.fromhex('31c0c3'),registered=False)
    with pytest.raises(UnhandledGuestException,match='no registered'):execute(engine,dispatcher,end)
    assert engine.uc.reg_read(UC_X86_REG_EBX)!=0x12345678
    assert dispatcher.events[-1]['status']=='unhandled_no_registered_handler'


def test_breakpoint_handler_must_change_context_eip_or_fault_budget_stops_it():
    engine,dispatcher,end,_=fixture(b'\xcc',bytes.fromhex('31c0c3'))
    with pytest.raises(UnsupportedDispatch,match='fault budget'):execute(engine,dispatcher,end)
    assert len(dispatcher.events)==8 and engine.uc.reg_read(UC_X86_REG_EBX)!=0x12345678


def test_search_disposition_is_still_unsupported():
    engine,dispatcher,end,_=fixture(b'\xf1',bytes.fromhex('b801000000c3'));execute(engine,dispatcher,end)
    assert 'Only SEH ContinueExecution' in dispatcher.unsupported and dispatcher.events[-1]['disposition']==1


def test_nested_breakpoint_in_handler_does_not_recurse():
    engine,dispatcher,end,_=fixture(b'\xf1',b'\xcc\xc3');execute(engine,dispatcher,end)
    assert 'Nested guest software traps' in dispatcher.unsupported and len(dispatcher.events)==1


@pytest.mark.parametrize('opcode',[bytes.fromhex('0f0b'),bytes.fromhex('cd03'),bytes.fromhex('31c931d2f7f1')])
def test_other_bad_instructions_and_interrupts_are_not_swallowed(opcode):
    engine,dispatcher,end,_=fixture(opcode,bytes.fromhex('31c0c3'))
    if opcode.startswith(b'\x0f\x0b'):
        with pytest.raises(UcError):execute(engine,dispatcher,end)
    else:
        execute(engine,dispatcher,end);assert 'vector/encoding' in dispatcher.unsupported
    assert engine.uc.reg_read(UC_X86_REG_EBX)!=0x12345678 and not dispatcher.events


def test_dispatcher_context_null_is_not_a_successful_zero_memory_read():
    handler=bytes.fromhex('8b4424108b1031c0c3')
    engine,dispatcher,end,_=fixture(b'\xf1',handler);execute(engine,dispatcher,end)
    assert 'Null/DispatcherContext' in dispatcher.unsupported


def test_hardware_trap_flag_transition_is_outside_the_declared_software_profile():
    handler=bytes.fromhex('8b44240c81b0c00000000001000031c0c3')
    engine,dispatcher,end,_=fixture(b'\xf1',handler);execute(engine,dispatcher,end)
    assert 'Hardware trap-flag transitions' in dispatcher.unsupported


def test_zero_address_is_not_a_valid_handler_even_when_the_backend_maps_page_zero():
    engine,dispatcher,end,_=fixture(b'\xf1',bytes.fromhex('31c0c3'))
    engine.uc.mem_write(0x7fffc,struct.pack('<I',0))
    with pytest.raises(UnsupportedDispatch,match='handler is not mapped executable'):
        execute(engine,dispatcher,end)
    assert not dispatcher.events


def test_opaque_breakpoint_parameters_are_not_read_as_invented_zeros():
    handler=bytes.fromhex('8b4424048b501831c0c3')
    engine,dispatcher,end,_=fixture(b'\xcc',handler);execute(engine,dispatcher,end)
    assert 'Opaque breakpoint exception parameters' in dispatcher.unsupported


def test_modeled_memcpy_cannot_bypass_the_exception_record_guard():
    engine,dispatcher,end,_=fixture(b'\xcc',bytes.fromhex('31c0c3'),modeled_api=True)
    engine.uc.emu_start(0x401000,end,timeout=100000,count=8);assert dispatcher.arm()==0x402000
    engine.uc.mem_write(0x401100,b'safe')
    engine.uc.mem_write(0x7fe00,struct.pack('<IIII',0x401200,0x401100,dispatcher.record_address+24,4))
    with pytest.raises(UnsupportedDispatch,match='Opaque breakpoint'):
        engine.apicall_handler.apicall(0,'memcpy',engine.uc,0x7fe00,False)
    assert engine.uc.mem_read(0x401100,4)==b'safe'


@pytest.mark.parametrize('flag',[0x100,0x400,0x40000])
def test_handler_entry_clears_execution_flags_but_preserves_fault_context(flag):
    engine,dispatcher,end,_=fixture(b'\xf1',bytes.fromhex('31c0c3'))
    flags=engine.uc.reg_read(dispatcher.register('EFLAGS'))|flag
    engine.uc.reg_write(dispatcher.register('EFLAGS'),flags)
    flags=engine.uc.reg_read(dispatcher.register('EFLAGS'))  # Reserved bit 1 is fixed by the CPU.
    dispatcher.software_pending={'kind':'icebp','code':0x80000004,'origin':0x401000,
                                'context_eip':0x401001,'exception_address':0x401001}
    assert dispatcher.arm()==0x402000
    assert engine.uc.reg_read(dispatcher.register('EFLAGS'))&(0x100|0x400|0x40000)==0
    context_flags=struct.unpack('<I',engine.uc.mem_read(dispatcher.context_address+0xc0,4))[0]
    assert context_flags==flags


def test_real_exception_handler_sees_cleared_direction_flag_and_continuation_restores_it():
    # pushfd/pop eax stores the actual handler-entry flags in benign guest RAM.
    handler=bytes.fromhex('9c58a30012400031c0c3')
    engine,dispatcher,end,_=fixture(b'\xf1',handler)
    engine.uc.reg_write(dispatcher.register('EFLAGS'),engine.uc.reg_read(dispatcher.register('EFLAGS'))|0x400)
    execute(engine,dispatcher,end)
    assert struct.unpack('<I',engine.uc.mem_read(0x401200,4))[0]&0x400==0
    assert engine.uc.reg_read(dispatcher.register('EFLAGS'))&0x400
    assert dispatcher.events[-1]['status']=='continue_execution'
