"""Pure memory string conversions, with no host locale or environment lookup."""
import struct
import pytest
from test_winapi_model import fixture_model
from unpacker.winapi_model import UnsupportedAPI


def test_utf16_conversion_query_terminator_and_buffer_boundaries():
    model,uc,_=fixture_model();convert=model.codepages.wide_to_multi
    uc.mem_write(0x100,'hello\0'.encode('utf-16le'))
    assert convert(uc,0,0,0x100,0xffffffff,0,0,0,0)==6
    assert convert(uc,1252,0,0x100,5,0x200,5,0,0x300)==5
    assert uc.mem_read(0x200,5)==b'hello' and uc.mem_read(0x300,4)==bytes(4)
    uc.mem_write(0x200,b'UNCHANGED')
    assert convert(uc,0,0,0x100,0xffffffff,0x200,5,0,0)==0
    assert model.last_error==122 and uc.mem_read(0x200,9)==b'UNCHANGED'


def test_utf8_conversion_handles_unicode_and_rejects_invalid_utf16_when_requested():
    model,uc,_=fixture_model();convert=model.codepages.wide_to_multi
    uc.mem_write(0x100,'€\0'.encode('utf-16le'))
    assert convert(uc,65001,0,0x100,0xffffffff,0x200,8,0,0)==4
    assert uc.mem_read(0x200,4)=='€\0'.encode('utf-8')
    uc.mem_write(0x100,b'\0\xd8')
    assert convert(uc,65001,0x80,0x100,1,0x200,8,0,0)==0 and model.last_error==1113


def test_cp1252_substitution_is_explicit_and_unsupported_best_fit_stops():
    model,uc,_=fixture_model();convert=model.codepages.wide_to_multi
    uc.mem_write(0x100,'α'.encode('utf-16le'))
    with pytest.raises(UnsupportedAPI):convert(uc,1252,0,0x100,1,0x200,8,0,0)
    assert convert(uc,1252,0x400,0x100,1,0x200,8,0,0x300)==1
    assert uc.mem_read(0x200,1)==b'?' and uc.mem_read(0x300,4)==struct.pack('<I',1)


def test_invalid_codepages_flags_and_counts_do_not_touch_output():
    model,uc,_=fixture_model();convert=model.codepages.wide_to_multi
    for cp,flags,count in [(932,0,1),(1252,1,1),(65001,0,0),(65001,0,0xfffffffe)]:
        assert convert(uc,cp,flags,0x100,count,0x200,8,0,0)==0
        assert model.last_error==(1004 if flags else 87)


def test_virtual_command_line_and_empty_environment_have_owned_memory():
    model,uc,_=fixture_model()
    ansi=model.command_line(uc,False);wide=model.command_line(uc,True)
    assert ansi==model.command_line(uc,False) and ansi!=wide
    assert uc.mem_read(ansi,len(model.PATH)+1)==model.PATH+b'\0'
    env=model.environment_strings(uc,True)
    assert uc.mem_read(env,4)==bytes(4) and model.free_environment(uc,env,False)==0
    assert model.free_environment(uc,env,True)==1 and model.free_environment(uc,env,True)==0
