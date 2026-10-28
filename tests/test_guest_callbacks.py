"""Synthetic CPU fixtures only: no acquired specimen or native execution."""
import struct
from types import SimpleNamespace as N
import pytest

unicorn=pytest.importorskip('unicorn')
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI


def model_fixture():
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
    uc.mem_map(0x1000,0x6000)
    handler=N(alloc_sizes={},hooks={},heaps={},next_heap_handle=0x70000000)
    engine=N(HOOK_ADDR=0x1000,apicall_handler=handler,sample=N(BASE_ADDR=0x2000),stop=lambda:uc.emu_stop())
    model=SelfFileModel(engine,b'benign',65536);model.install({})
    stub=b'\x8b\x04\x25'+struct.pack('<I',engine.HOOK_ADDR)+b'\xc3'
    uc.mem_write(0x1100,stub);uc.mem_write(0x1200,stub)
    handler.hooks[0x1100]='_initterm';handler.hooks[0x1200]='_initterm_e'
    errors=[]
    def hook(cpu,address,size,data):
        if address in handler.hooks:
            try:
                value,esp=handler.apicall(address,handler.hooks[address],cpu,cpu.reg_read(UC_X86_REG_ESP),False)
                if value is not None:cpu.mem_write(engine.HOOK_ADDR,struct.pack('<I',value))
                cpu.reg_write(UC_X86_REG_ESP,esp)
            except Exception as exc:errors.append(exc);cpu.emu_stop()
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    return model,uc,errors


def run_table(model,uc,values,checked=False):
    uc.mem_write(0x3000,struct.pack('<'+'I'*len(values),*values))
    uc.mem_write(0x5000,struct.pack('<III',0x2500,0x3000,0x3000+4*len(values)))
    uc.reg_write(UC_X86_REG_ESP,0x5000)
    uc.emu_start(0x1200 if checked else 0x1100,0x2500,count=1000)


def test_guest_initializers_execute_in_order_skip_null_and_preserve_cdecl_stack():
    model,uc,errors=model_fixture()
    uc.mem_write(0x2000,b'\xff\x05'+struct.pack('<I',0x4000)+b'\xc3')
    run_table(model,uc,[0,0x2000,0,0x2000])
    assert not errors and uc.mem_read(0x4000,4)==struct.pack('<I',2)
    assert uc.reg_read(UC_X86_REG_ESP)==0x5004
    assert uc.mem_read(0x5004,8)==struct.pack('<II',0x3000,0x3010)
    assert model.callbacks.calls==2 and model.callbacks.completed==1 and not model.callbacks.frames


def test_checked_initializer_stops_on_nonzero_result_without_skipping_it():
    model,uc,errors=model_fixture()
    uc.mem_write(0x2000,b'\xb8\x07\0\0\0\xc3')
    uc.mem_write(0x2100,b'\xff\x05'+struct.pack('<I',0x4000)+b'\xc3')
    run_table(model,uc,[0x2000,0x2100],True)
    assert not errors and uc.reg_read(UC_X86_REG_EAX)==7 and uc.mem_read(0x4000,4)==bytes(4)
    assert model.callbacks.calls==1


def test_void_initializer_ignores_callback_eax_and_checked_empty_table_returns_zero():
    model,uc,errors=model_fixture()
    uc.mem_write(0x2000,b'\xb8\x07\0\0\0\xc3')
    uc.mem_write(0x2100,b'\xff\x05'+struct.pack('<I',0x4000)+b'\xc3')
    run_table(model,uc,[0x2000,0x2100])
    assert not errors and uc.mem_read(0x4000,4)==struct.pack('<I',1)
    run_table(model,uc,[0,0],True)
    assert uc.reg_read(UC_X86_REG_EAX)==0


def test_nested_initializer_tables_resume_outer_callback():
    model,uc,errors=model_fixture()
    uc.mem_write(0x3100,struct.pack('<I',0x2100))
    code=b'\x68'+struct.pack('<I',0x3104)+b'\x68'+struct.pack('<I',0x3100)
    call=0x2000+len(code);code+=b'\xe8'+struct.pack('<i',0x1100-call-5)+b'\x83\xc4\x08\xc3'
    uc.mem_write(0x2000,code)
    uc.mem_write(0x2100,b'\xff\x05'+struct.pack('<I',0x4000)+b'\xc3')
    run_table(model,uc,[0x2000,0x2100])
    assert not errors and uc.mem_read(0x4000,4)==struct.pack('<I',2)
    assert model.callbacks.calls==3 and model.callbacks.completed==2 and not model.callbacks.frames


@pytest.mark.parametrize('begin,end',[(0x3001,0x3004),(0x3010,0x3000),(0,0x5000)])
def test_invalid_table_bounds_fail_explicitly(begin,end):
    model,uc,_=model_fixture()
    with pytest.raises(UnsupportedAPI):model.callbacks.start(uc,0x5000,begin,end)


def test_initializer_target_and_total_callback_budget_are_checked():
    model,uc,errors=model_fixture();run_table(model,uc,[0xdeadbeef])
    assert errors and isinstance(errors[0],UnsupportedAPI)
    model,uc,errors=model_fixture();model.callbacks.MAX_CALLS=1;uc.mem_write(0x2000,b'\xc3')
    run_table(model,uc,[0x2000,0x2000])
    assert errors and 'budget' in str(errors[0])


def test_stack_corruption_is_rejected_at_callback_continuation():
    model,uc,errors=model_fixture()
    uc.mem_write(0x2000,b'\xc2\x04\0');run_table(model,uc,[0x2000])
    assert errors and 'invalid stack' in str(errors[0])
