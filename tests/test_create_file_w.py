"""Wide virtual sample opens, share transitions and explicit unsupported modes."""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI

def fixture(name='C:\\sample.bin'):
    u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(0x1000,0x4000)
    m=SelfFileModel(N(sample=N(BASE_ADDR=0x400000),apicall_handler=N(),stop=lambda:None),b'known supplied bytes',65536)
    u.mem_write(0x1000,(name+'\0').encode('utf-16le'));return m,u

@pytest.mark.parametrize('name',['C:\\sample.bin','sample.bin','C:/SAMPLE.BIN'])
def test_unicode_open_reads_only_supplied_bytes_and_has_own_cursor(name):
    m,u=fixture(name);h=m.open_self_w(u,0x1000,0x80000000,1,0,3,0x80,0)
    assert h!=0xffffffff and m.handles[h]==('file',m.data)
    assert m.file_io.read(u,h,0x2000,len(m.data),0x3000,0)==1
    assert bytes(u.mem_read(0x2000,len(m.data)))==m.data
    assert m.close(u,h)==1 and h not in m.file_io.sharing

def test_sharing_violation_and_close_restore_availability():
    m,u=fixture();h=m.open_self_w(u,0x1000,0x80000000,0,0,3,0,0)
    assert m.open_self_w(u,0x1000,0x80000000,1,0,3,0,0)==0xffffffff and m.last_error==32
    assert m.close(u,h)==1
    a=m.open_self_w(u,0x1000,0x80000000,1,0,3,0,0);b=m.open_self_w(u,0x1000,0x80000000,1,0,3,0,0)
    assert a!=b and m.file_io.positions[a]==m.file_io.positions[b]==0

@pytest.mark.parametrize('args',[(0x40000000,1,0,3,0,0),(0x80000000,1,1,3,0,0),(0x80000000,1,0,2,0,0),(0x80000000,1,0,3,0x04000000,0),(0x80000000,1,0,3,0,1)])
def test_unsupported_write_security_creation_delete_template_never_allocate(args):
    m,u=fixture()
    with pytest.raises(UnsupportedAPI):m.open_self_w(u,0x1000,*args)
    assert not m.handles

def test_invalid_utf16_unreadable_and_foreign_files_do_not_open_host_data():
    m,u=fixture('C:\\private.bin');assert m.open_self_w(u,0x1000,0x80000000,1,0,3,0,0)==0xffffffff and m.last_error==2
    u.mem_write(0x1000,b'\0\xd8\0\0')
    with pytest.raises(UnsupportedAPI,match='UTF-16'):m.open_self_w(u,0x1000,0x80000000,1,0,3,0,0)
    with pytest.raises(UnsupportedAPI,match='readable'):m.open_self_w(u,0x9000,0x80000000,1,0,3,0,0)
    assert not m.handles

def test_wide_stdcall_consumes_seven_arguments():
    m,u=fixture();m.install({});u.mem_write(0x4000,struct.pack('<8I',0x12345678,0x1000,0x80000000,1,0,3,0,0))
    h,esp=m.handler.apicall(0,'CreateFileW',u,0x4000,False)
    assert h in m.handles and esp==0x401c and u.mem_read(esp,4)==struct.pack('<I',0x12345678)
