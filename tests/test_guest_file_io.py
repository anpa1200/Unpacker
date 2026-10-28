"""Benign synchronous file fixtures: no native code or host filesystem reads."""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_READ
from unpacker.winapi_model import SelfFileModel, UnsupportedAPI


def fixture(access=0x80000000, flags=0):
    uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0x1000,0x4000)
    model=SelfFileModel(N(sample=N(BASE_ADDR=0x400000),apicall_handler=N(),stop=lambda:None),b'benign fixture',65536)
    uc.mem_write(0x1000,model.PATH+b'\0')
    handle=model.open_self(uc,0x1000,access,1,0,3,flags,0)
    return model,uc,handle


def count(uc):return struct.unpack('<I',uc.mem_read(0x3000,4))[0]


def test_sequential_short_read_and_eof_are_actual_supplied_bytes():
    m,u,h=fixture()
    assert m.file_io.read(u,h,0x2000,6,0x3000,0)==1
    assert count(u)==6 and u.mem_read(0x2000,6)==b'benign'
    assert m.file_io.read(u,h,0x2000,99,0x3000,0)==1
    assert count(u)==8 and u.mem_read(0x2000,8)==b' fixture'
    assert m.file_io.read(u,h,0,5,0x3000,0)==1 and count(u)==0
    assert m.file_io.positions[h]==14 and m.file_io.bytes_read==14


def test_zero_read_allows_null_buffer_but_requires_win7_count_pointer():
    m,u,h=fixture()
    assert m.file_io.read(u,h,0,0,0x3000,0)==1 and count(u)==0
    assert m.file_io.read(u,h,0x2000,1,0,0)==0 and m.last_error==87
    assert m.file_io.positions[h]==0


@pytest.mark.parametrize('bad',[0,0xffffffff,0x70001234])
def test_invalid_handle_zeroes_count_and_returns_error(bad):
    m,u,h=fixture();u.mem_write(0x3000,b'xxxx')
    assert m.file_io.read(u,bad,0x2000,2,0x3000,0)==0
    assert m.last_error==6 and count(u)==0 and m.file_io.positions[h]==0


def test_metadata_only_access_cannot_read():
    m,u,h=fixture(access=0)
    assert m.file_io.read(u,h,0x2000,1,0x3000,0)==0 and m.last_error==5


@pytest.mark.parametrize('flags',[0x40000000,0x20000000])
def test_overlapped_and_unbuffered_modes_stop_explicitly(flags):
    m,u,h=fixture(flags=flags)
    with pytest.raises(UnsupportedAPI,match='not modeled'):m.file_io.read(u,h,0x2000,1,0x3000,0)
    assert m.file_io.positions[h]==0


@pytest.mark.parametrize('overlap,amount',[(0x4000,1),(0,65537)])
def test_read_budget_and_overlapped_pointer_reject_without_progress(overlap,amount):
    m,u,h=fixture()
    with pytest.raises(UnsupportedAPI):m.file_io.read(u,h,0x2000,amount,0x3000,overlap)
    assert m.file_io.positions[h]==0


@pytest.mark.parametrize('buffer',[0,0xfffffff9,0x6000,0x4fff])
def test_unwritable_buffer_cannot_advance_cursor(buffer):
    m,u,h=fixture()
    with pytest.raises(UnsupportedAPI,match='output range'):m.file_io.read(u,h,buffer,14,0x3000,0)
    assert m.file_io.positions[h]==0 and count(u)==0


def test_readonly_count_pointer_is_rejected_before_any_write():
    m,u,h=fixture();u.mem_protect(0x3000,0x1000,UC_PROT_READ)
    with pytest.raises(UnsupportedAPI,match='output range'):m.file_io.read(u,h,0x2000,1,0x3000,0)
    assert m.file_io.positions[h]==0


def test_independent_handles_and_close_cleanup():
    m,u,h=fixture();other=m.open_self(u,0x1000,0x80000000,1,0,3,0,0)
    assert m.file_io.read(u,h,0x2000,3,0x3000,0)==1
    assert m.file_io.positions[other]==0
    assert m.close(u,h)==1 and h not in m.file_io.positions and h not in m.file_io.options
    assert m.file_io.read(u,h,0x2000,1,0x3000,0)==0 and m.last_error==6
    assert other in m.handles


def test_seek_begin_current_end_negative_and_beyond_eof():
    m,u,h=fixture()
    assert m.file_io.seek(u,h,4,0,0)==4
    assert m.file_io.seek(u,h,0xfffffffe,0,1)==2
    assert m.file_io.seek(u,h,0xfffffffc,0,2)==10
    assert m.file_io.read(u,h,0x2000,4,0x3000,0)==1 and u.mem_read(0x2000,4)==b'ture'
    assert m.file_io.seek(u,h,0xffffffff,0,0)==0xffffffff and m.last_error==131
    assert m.file_io.positions[h]==14
    assert m.file_io.seek(u,h,100,0,0)==100
    assert m.file_io.read(u,h,0,1,0x3000,0)==1 and count(u)==0


def test_seek_signed_64_bit_and_success_ffffffff_clears_error():
    m,u,h=fixture();u.mem_write(0x3000,struct.pack('<I',1))
    assert m.file_io.seek(u,h,0,0x3000,0)==0 and count(u)==1
    u.mem_write(0x3000,struct.pack('<I',0xffffffff))
    assert m.file_io.seek(u,h,0xffffffff,0x3000,1)==0xffffffff
    assert count(u)==0 and m.file_io.positions[h]==0xffffffff and m.last_error==0
    assert m.file_io.seek(u,h,1,0,1)==0xffffffff and m.last_error==87
    assert m.file_io.positions[h]==0xffffffff


@pytest.mark.parametrize('method',[3,0xffffffff])
def test_invalid_seek_method_cannot_change_position(method):
    m,u,h=fixture()
    assert m.file_io.seek(u,h,1,0,method)==0xffffffff and m.last_error==87
    assert m.file_io.positions[h]==0


def test_seek_high_output_must_be_writable_before_cursor_changes():
    m,u,h=fixture();u.mem_write(0x3000,bytes(4));u.mem_protect(0x3000,0x1000,UC_PROT_READ)
    with pytest.raises(UnsupportedAPI,match='output range'):m.file_io.seek(u,h,2,0x3000,0)
    assert m.file_io.positions[h]==0


def test_real_stdcall_dispatch_for_read_and_seek():
    m,u,h=fixture();m.install({});ret=0x12345678
    u.mem_write(0x4000,struct.pack('<6I',ret,h,0x2000,3,0x3000,0))
    value,esp=m.handler.apicall(0,'ReadFile',u,0x4000,False)
    assert value==1 and esp==0x4014 and u.mem_read(esp,4)==struct.pack('<I',ret)
    assert count(u)==3 and u.mem_read(0x2000,3)==b'ben'
    u.mem_write(0x4000,struct.pack('<5I',ret,h,0,0,0))
    value,esp=m.handler.apicall(0,'SetFilePointer',u,0x4000,False)
    assert value==0 and esp==0x4010 and m.file_io.positions[h]==0
