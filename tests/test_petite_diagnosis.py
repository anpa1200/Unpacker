"""Reviewed benign arithmetic replay; this is not execution of a specimen."""
import pytest

unicorn=pytest.importorskip('unicorn')
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_EFLAGS


@pytest.mark.parametrize('word',[0x0300905a,0xfffa0005])
def test_length_complement_arithmetic_matches_independent_integer_result(word):
    # mov eax,ebx; not ebx; and eax,0xffff; shr ebx,16; xor ebx,eax.
    # The bounded fixture has no branch, API, syscall, memory operand or callback.
    code=bytes.fromhex('8bc3f7d325ffff0000c1eb1033d8')
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
    uc.mem_map(0x1000,4096);uc.mem_write(0x1000,code)
    uc.reg_write(UC_X86_REG_EBX,word);uc.reg_write(UC_X86_REG_EFLAGS,0x244)
    uc.emu_start(0x1000,0x1000+len(code),timeout=100000,count=16)
    expected=((~word&0xffffffff)>>16)^(word&0xffff)
    assert uc.reg_read(UC_X86_REG_EAX)==word&0xffff
    assert uc.reg_read(UC_X86_REG_EBX)==expected
    assert bool(uc.reg_read(UC_X86_REG_EFLAGS)&0x40)==(expected==0)
