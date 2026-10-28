"""Synthetic guest memory only; no host printf or specimen execution."""
import struct
import pytest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_ESP
from test_desktop_modules import installed
from unpacker.winapi_model import UnsupportedAPI
from unpacker.desktop_catalog import EXPORT_NAMES


def invoke(model,uc,fmt,values):
    uc.mem_write(0x100100,fmt+b'\0');uc.mem_write(0x100800,struct.pack('<'+'I'*(3+len(values)),0x100900,0x101000,0x100100,*values))
    return model.handler.apicall(0,'wsprintfA',uc,0x100800,False)


@pytest.mark.parametrize('fmt,values,expected',[
    (b'%d %i %u', [0xffffffff,0x80000000,0xffffffff],b'-1 -2147483648 4294967295'),
    (b'%08X %04x',[0x21,0xbe],b'00000021 00be'),
    (b'%-5s %.3s',[0x100300,0x100300],b'abcde abc'),
    (b'%06d',[0xffffffd6],b'-00042'),
    (b'%hd %hu %ld',[0xffff,0x1234ffff,0x80000000],b'-1 65535 -2147483648'),
    (b'%c %% %.4u',[65,7],b'A % 0007'),
    (b'plain',[],b'plain'),
    (b'%.0s',[0],b''),
])
def test_documented_ansi_integer_profile_and_cdecl_stack(fmt,values,expected):
    model,uc=installed();uc.mem_write(0x100300,b'abcde\0')
    value,esp=invoke(model,uc,fmt,values)
    assert value==len(expected) and esp==0x100800
    assert uc.mem_read(0x101000,len(expected)+1)==expected+b'\0'


@pytest.mark.parametrize('fmt,values',[ (b'%n',[0x101000]),(b'%f',[0]),(b'%ls',[0x100300]),
    (b'%*s',[20,0x100300]),(b'%1024s',[0x100300]),(b'%.9999d',[1]),(b'%#x',[1]),
    (b'%s',[0]),(b'%c',[0]),(b'%q',[0]) ])
def test_unsupported_or_unbounded_formats_stop_without_output_writes(fmt,values):
    model,uc=installed();uc.mem_write(0x101000,b'unchanged');uc.mem_write(0x100300,b'abc\0')
    with pytest.raises(UnsupportedAPI):invoke(model,uc,fmt,values)
    assert uc.mem_read(0x101000,9)==b'unchanged' and model.guest_format.calls==0


def test_aggregate_output_argument_and_readonly_destination_bounds():
    model,uc=installed();uc.mem_write(0x100300,b'A'*1023+b'\0');uc.mem_write(0x101000,b'safe')
    with pytest.raises(UnsupportedAPI):invoke(model,uc,b'%sA',[0x100300])
    with pytest.raises(UnsupportedAPI,match='argument budget'):invoke(model,uc,b'%d'*33,[1]*33)
    uc.mem_protect(0x101000,4096,1)
    with pytest.raises(UnsupportedAPI,match='writable'):invoke(model,uc,b'abc',[])
    assert uc.mem_read(0x101000,4)==b'safe'


def test_real_api_marker_formats_guest_bytes_and_returns_with_variadic_arguments_intact():
    model,uc=installed();view=model.desktop_modules.views['user32.dll'];address=view['exports']['wsprintfA']
    uc.mem_write(0x100100,b'%s:%d\0');uc.mem_write(0x100300,b'name\0')
    uc.mem_write(0x100800,struct.pack('<IIIII',0x100900,0x101000,0x100100,0x100300,217));uc.reg_write(UC_X86_REG_ESP,0x100800)
    uc.emu_start(address,0x100900,timeout=100000,count=8)
    assert uc.mem_read(0x101000,9)==b'name:217\0' and uc.reg_read(UC_X86_REG_EAX)==8
    assert uc.reg_read(UC_X86_REG_ESP)==0x100804 and model.engine.apicall_counter=={'wsprintfA':1}


def test_thiscall_and_stub_metadata_can_resolve_without_claiming_native_execution_support():
    assert '??1type_info@@UAE@XZ' in EXPORT_NAMES['msvcrt.dll']
    model,uc=installed();view=model.desktop_modules.views['msvcrt.dll']
    address=view['exports']['??1type_info@@UAE@XZ']
    with pytest.raises(UnsupportedAPI,match='execution semantics'):
        model.handler.apicall(address,'??1type_info@@UAE@XZ',uc,0x100800,False)


def test_va_list_api_uses_shared_format_semantics_with_stdcall_cleanup():
    model,uc=installed();address=model.desktop_modules.views['user32.dll']['exports']['wvsprintfA']
    uc.mem_write(0x100100,b'%s:%04d\0');uc.mem_write(0x100300,b'name\0')
    uc.mem_write(0x100500,struct.pack('<II',0x100300,42))
    uc.mem_write(0x100800,struct.pack('<IIII',0x100900,0x101000,0x100100,0x100500));uc.reg_write(UC_X86_REG_ESP,0x100800)
    uc.emu_start(address,0x100900,timeout=100000,count=8)
    assert uc.mem_read(0x101000,10)==b'name:0042\0' and uc.reg_read(UC_X86_REG_EAX)==9
    assert uc.reg_read(UC_X86_REG_ESP)==0x100810 and model.engine.apicall_counter=={'wvsprintfA':1}


def test_va_list_failure_reports_the_invoked_api_and_leaves_output_unchanged():
    model,uc=installed();uc.mem_write(0x100100,b'%n\0');uc.mem_write(0x101000,b'safe')
    uc.mem_write(0x100800,struct.pack('<IIII',0x100900,0x101000,0x100100,0x100500))
    with pytest.raises(UnsupportedAPI):model.handler.apicall(0,'wvsprintfA',uc,0x100800,False)
    assert model.unsupported[-1]['name']=='wvsprintfA' and uc.mem_read(0x101000,4)==b'safe'
