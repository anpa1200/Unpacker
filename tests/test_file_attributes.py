"""Structured virtual-file metadata. No host file/stat/network operation."""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI


def fixture(name=r'C:\sample.bin'):
    u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(0x1000,0x3000)
    m=SelfFileModel(N(sample=N(BASE_ADDR=0x400000),apicall_handler=N(),stop=lambda:None),b'benign bytes',65536)
    u.mem_write(0x1000,(name+'\0').encode('utf-16le'));return m,u


@pytest.mark.parametrize('name',[r'C:\sample.bin','sample.bin',r'C:/SAMPLE.BIN'])
def test_present_file_returns_complete_consistent_36_byte_record(name):
    m,u=fixture(name);u.mem_write(0x2000,b'x'*40)
    assert m.file_attributes.query_w(u,0x1000,0,0x2000)==1
    attrs,creation,access,write,high,low=struct.unpack('<IQQQII',u.mem_read(0x2000,36))
    assert attrs==0x80 and high==0 and low==len(m.data)
    assert creation==access==write==116444736000000000
    assert u.mem_read(0x2024,4)==b'xxxx'
    assert m.file_attributes.facts()['host_metadata_access'] is False


@pytest.mark.parametrize('path,error',[(r'C:\absent.bin',2),(r'C:\absent\file.bin',3)])
def test_absent_virtual_path_does_not_modify_output_or_access_host(path,error):
    m,u=fixture(path);u.mem_write(0x2000,b'x'*36)
    assert m.file_attributes.query_w(u,0x1000,0,0x2000)==0 and m.last_error==error
    assert u.mem_read(0x2000,36)==b'x'*36


@pytest.mark.parametrize('name',[r'\\server\share\file',r'D:\secret','C:\\','x'*261])
def test_undeclared_path_namespaces_and_directories_remain_unsupported(name):
    m,u=fixture(name)
    with pytest.raises(UnsupportedAPI):m.file_attributes.query_w(u,0x1000,0,0x2000)


@pytest.mark.parametrize('output',[0,0x3fff,0xfffffff0])
def test_invalid_output_range_never_reports_success(output):
    m,u=fixture()
    with pytest.raises(UnsupportedAPI):m.file_attributes.query_w(u,0x1000,0,output)


def test_invalid_information_class_and_null_name_return_error_without_writes():
    m,u=fixture();u.mem_write(0x2000,b'x'*36)
    assert m.file_attributes.query_w(u,0x1000,1,0x2000)==0 and m.last_error==87
    assert m.file_attributes.query_w(u,0,0,0x2000)==0 and m.last_error==87
    assert u.mem_read(0x2000,36)==b'x'*36


def test_malformed_unicode_and_unreadable_names_stop_explicitly():
    m,u=fixture();u.mem_write(0x1000,b'\x00\xd8\x00\x00')
    with pytest.raises(UnsupportedAPI,match='UTF-16'):m.file_attributes.query_w(u,0x1000,0,0x2000)
    with pytest.raises(UnsupportedAPI,match='readable'):m.file_attributes.query_w(u,0x9000,0,0x2000)


def test_stdcall_cleans_three_arguments_and_keeps_return_address():
    m,u=fixture();m.install({});u.mem_write(0x3000,struct.pack('<4I',0x12345678,0x1000,0,0x2000))
    value,esp=m.handler.apicall(0,'GetFileAttributesExW',u,0x3000,False)
    assert value==1 and esp==0x300c and u.mem_read(esp,4)==struct.pack('<I',0x12345678)
