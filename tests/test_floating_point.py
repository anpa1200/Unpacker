"""Guest CPU register contracts only; no acquired sample execution."""
from types import SimpleNamespace as N
import pytest
unicorn=pytest.importorskip('unicorn')
from unicorn.x86_const import UC_X86_REG_FPCW,UC_X86_REG_MXCSR
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI


def fixture_model():
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
    model=SelfFileModel(N(uc=uc,apicall_handler=N(),stop=uc.emu_stop),b'benign',65536)
    return model,uc


def test_crt_default_and_precision_rounding_change_real_guest_control_registers():
    model,uc=fixture_model();control=model.floating_point.control
    assert control(uc,0,0)==0x9001f
    assert control(uc,0x20000,0x30000)==0xa001f
    assert uc.reg_read(UC_X86_REG_FPCW)&0x300==0
    assert control(uc,0x200,0x300)==0xa021f
    assert (uc.reg_read(UC_X86_REG_FPCW)>>10)&3==2
    assert (uc.reg_read(UC_X86_REG_MXCSR)>>13)&3==2
    assert control(uc,0x10000,0x30000)==0x9021f


def test_exception_masks_denormal_difference_and_ambiguity_are_observable():
    model,uc=fixture_model();control=model.floating_point.control
    value=control(uc,0x10,0x8001f)
    assert value&0x8001f==0x80010  # _controlfp preserves denormal mask.
    assert not uc.reg_read(UC_X86_REG_FPCW)&(1<<2)
    assert not uc.reg_read(UC_X86_REG_MXCSR)&(1<<9)
    assert control(uc,0,0x80000,True)&0x80000==0
    uc.reg_write(UC_X86_REG_MXCSR,0x1f80)
    assert control(uc,0,0)&0x80000000


def test_reserved_precision_and_unknown_masks_fail_explicitly():
    model,uc=fixture_model()
    with pytest.raises(UnsupportedAPI):model.floating_point.control(uc,0x30000,0x30000)
    with pytest.raises(UnsupportedAPI):model.floating_point.control(uc,0,0x80000000)
