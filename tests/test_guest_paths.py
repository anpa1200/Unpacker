"""Memory-only Win32 path/palette contract tests, with no filesystem access."""
import struct
import pytest
from test_winapi_model import fixture_model
from unpacker.winapi_model import UnsupportedAPI


@pytest.mark.parametrize('name,expected',[
    (b'sample.bin',b'C:\\sample.bin'),(b'C:sample.bin',b'C:\\sample.bin'),
    (b'c:/dir/../sample.bin',b'C:\\sample.bin'),
    (b'\\dir\\file.bin',b'C:\\dir\\file.bin'),
    (b'..\\..\\file.bin',b'C:\\file.bin'),(b'dir\\',b'C:\\dir\\'),
    (b'.',b'C:\\'),(b'caf\xe9.bin',b'C:\\caf\xe9.bin')])
def test_full_path_normalization_length_and_file_part(name,expected):
    model,uc,_=fixture_model();uc.mem_write(0x100,name+b'\0')
    size=model.paths.full_path(uc,0x100,0,0,0)
    assert size==len(expected)+1
    uc.mem_write(0x300,b'unchanged')
    assert model.paths.full_path(uc,0x100,size-1,0x300,0x400)==size
    assert uc.mem_read(0x300,9)==b'unchanged'
    assert model.paths.full_path(uc,0x100,size,0x300,0x400)==len(expected)
    assert uc.mem_read(0x300,size)==expected+b'\0'
    pointer=struct.unpack('<I',uc.mem_read(0x400,4))[0]
    assert pointer==(0 if expected.endswith(b'\\') else 0x300+expected.rfind(b'\\')+1)


@pytest.mark.parametrize('name',[b'',b'\\\\server\\share',b'\\\\?\\C:\\sample',
    b'D:\\file',b'file:stream',b'file.',b'file ',b'NUL.txt',b'COM1',b'file*'])
def test_unmodeled_namespace_stops_without_writing_output(name):
    model,uc,stops=fixture_model();uc.mem_write(0x100,name+b'\0');uc.mem_write(0x300,b'sentinel')
    with pytest.raises(UnsupportedAPI):model.paths.full_path(uc,0x100,100,0x300,0)
    assert uc.mem_read(0x300,8)==b'sentinel' and stops==[True]


def test_path_pointer_and_capacity_limits_and_stdcall():
    model,uc,_=fixture_model();uc.mem_write(0x100,b'sample.bin\0')
    for capacity,buffer,part in [(100,0,0),(100,0xfffffff8,0),(100,0x300,0xffffffff),(65537,0x300,0)]:
        with pytest.raises(UnsupportedAPI):model.paths.full_path(uc,0x100,capacity,buffer,part)
    model.install({});uc.mem_write(0x500,struct.pack('<IIIII',0x401234,0x100,100,0x300,0x400))
    assert model.handler.apicall(0,'GetFullPathNameA',uc,0x500,False)==(13,0x510)
    assert uc.mem_read(0x510,4)==struct.pack('<I',0x401234)


def test_guest_palette_is_fixed_and_unknown_colors_stop():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x100,struct.pack('<II',0x401234,15))
    assert model.handler.apicall(0,'GetSysColor',uc,0x100,False)==(0xf0f0f0,0x104)
    assert model.display.system_color(uc,16)==0xa0a0a0
    assert model.display.system_color(uc,18)==0 and model.display.system_color(uc,20)==0xffffff
    assert model.display.system_color(uc,6)==0x646464
    assert set(model.display.colors)==set(range(31))-{25}
    assert all(0<=model.display.system_color(uc,i)<=0xffffff for i in model.display.colors)
    with pytest.raises(UnsupportedAPI):model.display.system_color(uc,25)
    with pytest.raises(UnsupportedAPI):model.display.system_color(uc,999)


def test_char_upper_exact_count_embedded_null_tail_and_stdcall():
    model,uc,_=fixture_model();uc.mem_write(0x100,b'ab\0cd!tail')
    assert model.paths.upper_ascii(uc,0,0)==0
    model.install({});uc.mem_write(0x500,struct.pack('<III',0x401234,0x100,5))
    assert model.handler.apicall(0,'CharUpperBuffA',uc,0x500,False)==(5,0x508)
    assert uc.mem_read(0x100,10)==b'AB\0CD!tail'


@pytest.mark.parametrize('value,count',[(b'\xe9',1),(b'a',65537)])
def test_char_upper_rejects_unmodeled_nls_or_excess_before_writing(value,count):
    model,uc,_=fixture_model();uc.mem_write(0x100,value)
    with pytest.raises(UnsupportedAPI):model.paths.upper_ascii(uc,0x100,count)
    assert uc.mem_read(0x100,len(value))==value
