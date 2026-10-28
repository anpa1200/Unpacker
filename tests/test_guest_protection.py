"""Benign guest pages and tiny load/store probes, never specimen code."""
import struct
from types import SimpleNamespace as N
import pytest

unicorn = pytest.importorskip("unicorn")
from unpacker.winapi_model import SelfFileModel, UnsupportedAPI


def fixture():
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x1000, 0x2000, 7)
    uc.mem_map(0x4000, 0x1000, 3)
    handler = N(alloc_sizes={}, atn={(0x1000,0x3000):"code"}, ntp={"code":(True,True,True)})
    stopped = []
    engine = N(uc=uc, sample=N(), apicall_handler=handler, stop=lambda:stopped.append(True))
    return SelfFileModel(engine,b"benign",1024*1024), uc, stopped


def permissions(uc, address):
    return next(p for lo,hi,p in uc.mem_regions() if lo <= address <= hi)


def test_return_old_protection_and_restore_transition():
    model,uc,_ = fixture()
    assert model.protection.protect(uc,0x1100,50,2,0x4000) == 1
    assert struct.unpack("<I",uc.mem_read(0x4000,4))[0] == 0x40
    assert permissions(uc,0x1000) == 1 and permissions(uc,0x2000) == 7
    assert model.handler.ntp["code"] == (False,True,False)
    assert model.protection.protect(uc,0x1100,50,0x40,0x4000) == 1
    assert struct.unpack("<I",uc.mem_read(0x4000,4))[0] == 2
    assert permissions(uc,0x1000) == 7
    assert model.protection.calls == 2


def test_readonly_is_enforced_for_guest_store():
    model,uc,_ = fixture()
    # mov byte ptr [0x1100],0x41; no syscall, import, callback or branch.
    code = bytes.fromhex("c6050011000041")
    uc.mem_write(0x2000,code)
    model.protection.protect(uc,0x1100,1,2,0x4000)
    with pytest.raises(unicorn.UcError):
        uc.emu_start(0x2000,0x2000+len(code),timeout=100000,count=4)
    assert uc.mem_read(0x1100,1) == b"\0"


def test_page_boundary_and_first_page_old_value():
    model,uc,_ = fixture()
    uc.mem_protect(0x2000,0x1000,1)
    assert model.protection.protect(uc,0x1fff,2,4,0x4000) == 1
    assert permissions(uc,0x1000) == permissions(uc,0x2000) == 3
    assert struct.unpack("<I",uc.mem_read(0x4000,4))[0] == 0x40


@pytest.mark.parametrize("address,size,pointer", [(0x1000,0,0x4000),(0xfffffff0,32,0x4000),
    (0x1000,1,0),(0x1000,1,0x7000),(0x1000,1,0x2fff),(0x2fff,2,0x4000)])
def test_invalid_arguments_do_not_modify_pages_or_output(address,size,pointer):
    model,uc,_ = fixture()
    uc.mem_protect(0x2000,0x1000,1)
    uc.mem_write(0x4000,b"safe")
    before=list(uc.mem_regions())
    assert model.protection.protect(uc,address,size,4,pointer) == 0
    assert list(uc.mem_regions()) == before and uc.mem_read(0x4000,4) == b"safe"
    assert model.protection.calls == 0


def test_unknown_modifiers_stop_without_faking_success():
    model,uc,stopped = fixture()
    with pytest.raises(UnsupportedAPI): model.protection.protect(uc,0x1000,1,0x104,0x4000)
    assert permissions(uc,0x1000) == 7 and stopped == [True]


def test_later_allocation_and_stdcall_dispatch():
    model,uc,_ = fixture()
    uc.mem_map(0x6000,0x1000,3)
    model.handler.alloc_sizes[0x6000] = 0x1000
    model.install({})
    uc.mem_write(0x4100,struct.pack("<5I",0x12345678,0x6000,1,2,0x4000))
    value,esp=model.handler.apicall(0,"VirtualProtect",uc,0x4100,False)
    assert value == 1 and esp == 0x4110
    assert uc.mem_read(esp,4) == struct.pack("<I",0x12345678)
    assert struct.unpack("<I",uc.mem_read(0x4000,4))[0] == 4
    assert permissions(uc,0x6000) == 1


@pytest.mark.parametrize('api',['VirtualProtect','VirtualProtectEx'])
def test_deferred_protection_returns_to_caller_once_without_api_block_reentry(api):
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ESP
    model,uc,_ = fixture()
    model.install({})
    uc.mem_map(0x6000,0x1000,7)
    uc.mem_write(0x6000,b"\xc3")
    # push outptr; push PAGE_READONLY; push 1; push target; call stub;
    # mov ebx,0x12345678. Only the tiny synthetic API wrapper is executed.
    prefix=bytes.fromhex("68004000006a026a016800100000")
    if api=='VirtualProtectEx':prefix+=bytes.fromhex('6aff')
    code=prefix+b'\xe8'+struct.pack('<i',0x6000-(0x2000+len(prefix)+5))+bytes.fromhex('bb78563412')
    uc.mem_write(0x2000,code)
    uc.reg_write(UC_X86_REG_ESP,0x4f00)
    calls=[]
    def hook(uc,address,size,user):
        if address==0x6000:
            calls.append(address)
            ret,esp=model.handler.apicall(address,api,uc,uc.reg_read(UC_X86_REG_ESP),False)
            uc.reg_write(UC_X86_REG_EAX,ret)
            uc.reg_write(UC_X86_REG_ESP,esp)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    start=0x2000
    for _ in range(3):
        model.engine._unpacker_inside_emulation=True
        try:uc.emu_start(start,0x2000+len(code),timeout=100000,count=32)
        finally:model.engine._unpacker_inside_emulation=False
        resume=model.protection.take_resume(uc)
        if resume is None:break
        start=resume
    assert calls==[0x6000] and model.protection.calls==1
    assert uc.reg_read(UC_X86_REG_ESP)==0x4f00
    assert uc.reg_read(UC_X86_REG_EBX)==0x12345678 and uc.reg_read(UC_X86_REG_EAX)==1
    assert permissions(uc,0x1000)==1


def test_virtual_protect_ex_validates_real_current_handle_rights_and_changes_guest_pages():
    m,u,_=fixture();m.handler.processid=1234;h=m.open_current_process(u,8,0,1234)
    assert m.protect_current_process(u,h,0x1100,1,2,0x4000)==1
    assert permissions(u,0x1000)==1 and struct.unpack('<I',u.mem_read(0x4000,4))[0]==0x40


@pytest.mark.parametrize('kind,state',[('file',b''),('process',{'pid':999,'access':8}),('process',{'pid':1234,'access':0x400})])
def test_virtual_protect_ex_rejects_wrong_type_foreign_pid_or_missing_rights_before_mutation(kind,state):
    m,u,_=fixture();m.handler.processid=1234;h=m.handle(kind,state);before=list(u.mem_regions())
    with pytest.raises(UnsupportedAPI):m.protect_current_process(u,h,0x1100,1,2,0x4000)
    assert list(u.mem_regions())==before and m.protection.calls==0
