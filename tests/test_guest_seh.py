"""Reviewed synthetic CPU programs for the bounded PE32 SEH profile."""
import struct
from types import SimpleNamespace as N

import pytest

unicorn=pytest.importorskip('unicorn')
from unicorn.x86_const import UC_X86_REG_EIP,UC_X86_REG_ESP,UC_X86_REG_ECX,UC_X86_REG_EBX,UC_X86_REG_EAX,UC_X86_REG_FPCW
from unpacker.guest_seh import AccessViolationDispatcher,UnsupportedDispatch


def fixture(handler):
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
    uc.mem_map(0,0x100000);uc.mem_map(0x200000,4096);uc.mem_map(0x401000,8192)
    # xor eax,eax; mov [eax],ecx; mov ebx,0x12345678; nop.
    program=bytes.fromhex('31c08908bb7856341290')
    uc.mem_write(0x401000,program);uc.mem_write(0x402000,handler)
    uc.mem_write(0x7fff8,struct.pack('<II',0xffffffff,0x402000))
    uc.mem_write(0x200000,struct.pack('<I',0x7fff8))
    uc.reg_write(UC_X86_REG_ESP,0x7fff8);uc.reg_write(UC_X86_REG_ECX,0x55667788)
    engine=N(uc=uc,STACK_ADDR=0,STACK_SIZE=0x100000,TEB_BASE=0x200000,
             stop=uc.emu_stop,apicall_handler=N(hooks={},apicall=lambda *args:(None,args[3])))
    dispatcher=AccessViolationDispatcher(engine)
    def invalid(uc,access,address,size,value,user):
        engine._unpacker_memory_fault={'access':access,'address':address,'size':size}
        uc.emu_stop();return False
    def code(uc,address,size,user):
        if address in engine.apicall_handler.hooks:
            try:
                value,esp=engine.apicall_handler.apicall(address,engine.apicall_handler.hooks[address],uc,uc.reg_read(UC_X86_REG_ESP),False)
                uc.reg_write(UC_X86_REG_ESP,esp)
            except UnsupportedDispatch:pass
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,invalid)
    uc.hook_add(unicorn.UC_HOOK_CODE,code)
    def memory(uc,access,address,size,value,user):
        try:dispatcher.check_context_access(address,size)
        except UnsupportedDispatch:pass
    uc.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)
    return engine,dispatcher,0x401000+len(program)


def execute(engine,dispatcher,end):
    start=0x401000
    for _ in range(16):
        try:engine.uc.emu_start(start,end,timeout=100000,count=1000)
        except unicorn.UcError:pass
        if dispatcher.unsupported:return
        resume=dispatcher.take_resume()
        if resume is not None:start=resume;continue
        handler=dispatcher.arm()
        if handler is not None:start=handler;continue
        return
    raise AssertionError('Synthetic SEH fixture exceeded its bounded run count')


def test_handler_can_update_context_and_resume_with_original_integer_registers():
    # Read CONTEXT from third cdecl argument; skip the two-byte faulting store;
    # deliberately clobber ECX; return ContinueExecution (zero).
    handler=bytes.fromhex('8b44240c8380b800000002b9efbeadde31c0c3')
    engine,dispatcher,end=fixture(handler)
    execute(engine,dispatcher,end)
    assert engine.uc.reg_read(UC_X86_REG_EIP)==end
    assert engine.uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert engine.uc.reg_read(UC_X86_REG_ECX)==0x55667788
    assert engine.uc.reg_read(UC_X86_REG_EAX)==0
    assert dispatcher.events[-1]['status']=='continue_execution'
    assert dispatcher.events[-1]['fault_eip']==0x401002
    assert not dispatcher.active and not dispatcher.unsupported


def test_null_page_is_unmapped_without_moving_the_existing_stack():
    engine,dispatcher,end=fixture(bytes.fromhex('31c0c3'))
    with pytest.raises(unicorn.UcError):engine.uc.mem_read(0,4)
    assert engine.uc.reg_read(UC_X86_REG_ESP)==0x7fff8
    assert struct.unpack('<I',engine.uc.mem_read(0x200008,4))[0]==4096


def test_search_disposition_is_explicitly_unsupported():
    engine,dispatcher,end=fixture(bytes.fromhex('b801000000c3'))
    execute(engine,dispatcher,end)
    assert 'Only SEH ContinueExecution' in dispatcher.unsupported
    assert dispatcher.events[-1]['disposition']==1


def test_nested_fault_stops_instead_of_recursing():
    engine,dispatcher,end=fixture(bytes.fromhex('31c08900c3'))
    with pytest.raises(UnsupportedDispatch,match='Nested guest access'):
        execute(engine,dispatcher,end)


def test_handler_floating_point_changes_do_not_escape_context_restoration():
    handler=bytes.fromhex('d92d002140008b44240c8380b80000000231c0c3')
    engine,dispatcher,end=fixture(handler)
    engine.uc.mem_write(0x402100,struct.pack('<H',0x037f))
    engine.uc.reg_write(UC_X86_REG_FPCW,0x027f)
    execute(engine,dispatcher,end)
    assert engine.uc.reg_read(UC_X86_REG_EIP)==end
    assert engine.uc.reg_read(UC_X86_REG_FPCW)==0x027f


def test_unmodeled_context_payload_is_not_read_as_invented_state():
    # Load CONTEXT pointer, then attempt to read its absent floating-save area.
    handler=bytes.fromhex('8b44240c8b401c31c0c3')
    engine,dispatcher,end=fixture(handler)
    execute(engine,dispatcher,end)
    assert 'Unsupported debug/floating-point SEH context access' in dispatcher.unsupported


def test_declared_segment_context_fields_remain_readable():
    handler=bytes.fromhex('8b44240c8b88900000008380b80000000231c0c3')
    engine,dispatcher,end=fixture(handler)
    execute(engine,dispatcher,end)
    assert engine.uc.reg_read(UC_X86_REG_EIP)==end and not dispatcher.unsupported


def test_stdcall_handler_return_is_not_silently_treated_as_cdecl():
    engine,dispatcher,end=fixture(bytes.fromhex('31c0c21000'))
    execute(engine,dispatcher,end)
    assert 'return stack or calling convention' in dispatcher.unsupported


def test_privileged_context_flag_changes_are_explicitly_rejected():
    handler=bytes.fromhex('8b44240c81b0c00000000030000031c0c3')
    engine,dispatcher,end=fixture(handler)
    execute(engine,dispatcher,end)
    assert 'privileged flag changes' in dispatcher.unsupported
