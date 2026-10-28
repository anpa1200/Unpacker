"""Benign state transitions over isolated guest mutexes, no host mutex calls."""
import struct
from types import SimpleNamespace as N
import pytest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unpacker.winapi_model import SelfFileModel,UnsupportedAPI


def fixture():
    u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(0x1000,0x3000)
    m=SelfFileModel(N(sample=N(BASE_ADDR=0x400000),apicall_handler=N(),stop=lambda:None),b'benign',65536)
    u.mem_write(0x1000,b'fixture\0');return m,u


def test_initial_owner_and_recursive_wait_require_matching_releases():
    m,u=fixture();h=m.mutexes.create(u,0,1,0x1000);obj=m.handles[h][1]
    assert obj['owner']==1 and obj['depth']==1 and m.last_error==0
    assert m.mutexes.wait(u,h,0xffffffff)==0 and obj['depth']==2
    assert m.mutexes.release(u,h)==1 and obj['owner']==1 and obj['depth']==1
    assert m.mutexes.release(u,h)==1 and obj['owner'] is None and obj['depth']==0
    assert m.mutexes.release(u,h)==0 and m.last_error==288


def test_existing_name_opens_new_handle_and_ignores_initial_owner():
    m,u=fixture();a=m.mutexes.create(u,0,0,0x1000);b=m.mutexes.create(u,0,1,0x1000)
    assert a!=b and m.handles[a][1] is m.handles[b][1] and m.last_error==183
    assert m.handles[b][1]['owner'] is None and m.handles[b][1]['depth']==0
    assert m.mutexes.wait(u,b,0)==0 and m.handles[a][1]['depth']==1


def test_reopening_owned_mutex_does_not_recursively_acquire_it():
    m,u=fixture();a=m.mutexes.create(u,0,1,0x1000);b=m.mutexes.create(u,0,1,0x1000)
    assert m.handles[a][1]['depth']==1 and m.handles[b][1]['references']==2


def test_case_sensitive_names_and_local_prefix_alias():
    m,u=fixture();a=m.mutexes.create(u,0,0,0x1000)
    u.mem_write(0x1100,b'Local\\fixture\0');b=m.mutexes.create(u,0,0,0x1100)
    u.mem_write(0x1200,b'Fixture\0');c=m.mutexes.create(u,0,0,0x1200)
    assert m.handles[a][1] is m.handles[b][1] and m.handles[c][1] is not m.handles[a][1]


def test_unnamed_mutexes_are_distinct_and_close_preserves_other_handles():
    m,u=fixture();a=m.mutexes.create(u,0,1,0);b=m.mutexes.create(u,0,1,0)
    assert m.handles[a][1] is not m.handles[b][1] and not m.mutexes.named
    assert m.close(u,a)==1 and b in m.handles and m.close(u,a)==0


def test_last_close_destroys_named_object_without_releasing_other_reference():
    m,u=fixture();a=m.mutexes.create(u,0,1,0x1000);b=m.mutexes.create(u,0,0,0x1000);obj=m.handles[a][1]
    assert m.close(u,a)==1 and obj['references']==1 and obj['owner']==1
    assert m.close(u,b)==1 and not m.mutexes.named
    c=m.mutexes.create(u,0,0,0x1000)
    assert m.last_error==0 and m.handles[c][1] is not obj and m.handles[c][1]['owner'] is None


@pytest.mark.parametrize('handle',[0,1234])
def test_invalid_handles_fail_and_never_create_objects(handle):
    m,u=fixture()
    assert m.mutexes.wait(u,handle,0)==0xffffffff and m.last_error==6
    assert m.mutexes.release(u,handle)==0 and not m.handles


@pytest.mark.parametrize('name',[b'Global\\fixture',b'private\\fixture',b'',b'x'*261])
def test_unsupported_namespace_and_name_reject_without_handles(name):
    m,u=fixture();u.mem_write(0x1000,name+b'\0')
    with pytest.raises(UnsupportedAPI):m.mutexes.create(u,0,0,0x1000)
    assert not m.handles and not m.mutexes.named


def test_nonnull_security_attributes_cannot_claim_inherited_acl_semantics():
    m,u=fixture()
    with pytest.raises(UnsupportedAPI,match='Security'):m.mutexes.create(u,0x2000,1,0x1000)
    assert not m.handles


def test_handle_budget_failure_does_not_mutate_mutex_namespace():
    m,u=fixture()
    for i in range(128):m.handle('file',b'')
    with pytest.raises(UnsupportedAPI,match='Handle budget'):m.mutexes.create(u,0,1,0x1000)
    assert len(m.handles)==128 and not m.mutexes.named


def test_foreign_owner_and_wait_on_other_object_types_never_fake_success():
    m,u=fixture();h=m.mutexes.create(u,0,0,0x1000);obj=m.handles[h][1];obj['owner']=2
    with pytest.raises(UnsupportedAPI,match='External owner'):m.mutexes.wait(u,h,0)
    assert obj['owner']==2 and obj['depth']==0
    other=m.handle('file',b'')
    with pytest.raises(UnsupportedAPI,match='object type'):m.mutexes.wait(u,other,0)


def test_stdcall_create_wait_release_and_cleanup_are_real_state_transitions():
    m,u=fixture();m.install({});ret=0x12345678
    u.mem_write(0x2000,struct.pack('<4I',ret,0,0,0x1000))
    h,esp=m.handler.apicall(0,'CreateMutexA',u,0x2000,False)
    assert esp==0x200c and h in m.handles and m.handles[h][1]['owner'] is None
    u.mem_write(0x2000,struct.pack('<3I',ret,h,0))
    value,esp=m.handler.apicall(0,'WaitForSingleObject',u,0x2000,False)
    assert value==0 and esp==0x2008 and m.handles[h][1]['depth']==1
    u.mem_write(0x2000,struct.pack('<2I',ret,h))
    value,esp=m.handler.apicall(0,'ReleaseMutex',u,0x2000,False)
    assert value==1 and esp==0x2004 and m.handles[h][1]['owner'] is None
    assert m.close(u,h)==1 and m.mutexes.facts()['open_handles']==0


def test_release_of_nonmutex_object_returns_invalid_handle_without_mutation():
    m,u=fixture();h=m.handle('file',b'benign')
    assert m.mutexes.release(u,h)==0 and m.last_error==6 and h in m.handles
