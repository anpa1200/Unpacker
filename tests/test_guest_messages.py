"""Memory-only registered-message names, with no host UI/atom-table calls."""
import struct

import pytest

from test_winapi_model import fixture_model
from unpacker.winapi_model import UnsupportedAPI


def test_same_name_and_ascii_case_reuse_one_identifier():
    model,uc,_=fixture_model();registry=model.registered_messages
    uc.mem_write(0x100,b'Example.Message\0');uc.mem_write(0x200,b'example.message\0')
    first=registry.register(uc,0x100)
    assert 0xc000<=first<=0xffff
    assert registry.register(uc,0x200)==first and len(registry.names)==1
    uc.mem_write(0x200,b'Other.Message\0')
    assert registry.register(uc,0x200)!=first and len(registry.names)==2


def test_ansi_and_utf16_calls_share_one_guest_namespace():
    model,uc,_=fixture_model();registry=model.registered_messages
    uc.mem_write(0x100,b'Guest.Name\0');uc.mem_write(0x200,'Guest.Name\0'.encode('utf-16le'))
    assert registry.register(uc,0x100)==registry.register(uc,0x200,True)
    assert len(registry.names)==1


def test_each_specimen_session_has_private_bounded_state():
    first,uc,_=fixture_model();second,_,_=fixture_model()
    uc.mem_write(0x100,b'Private\0');first.registered_messages.register(uc,0x100)
    assert not second.registered_messages.names


def test_255_character_name_is_accepted_but_256_is_not():
    model,uc,_=fixture_model();uc.mem_write(0x100,b'x'*255+b'\0')
    assert model.registered_messages.register(uc,0x100)==0xc000
    uc.mem_write(0x100,b'x'*256+b'\0')
    with pytest.raises(UnsupportedAPI,match='exceeds 255'):
        model.registered_messages.register(uc,0x100)


@pytest.mark.parametrize('data',[b'\0',b'\x80\0',b'#123\0'])
def test_unsupported_name_profiles_stop_explicitly(data):
    model,uc,stops=fixture_model();uc.mem_write(0x100,data)
    with pytest.raises(UnsupportedAPI):model.registered_messages.register(uc,0x100)
    assert stops==[True] and not model.registered_messages.names


def test_null_and_unreadable_names_stop_without_registration():
    for address in [0,0x200000]:
        model,uc,_=fixture_model()
        with pytest.raises(UnsupportedAPI):model.registered_messages.register(uc,address)
        assert not model.registered_messages.names


def test_name_budget_preserves_existing_registrations(monkeypatch):
    model,uc,_=fixture_model();registry=model.registered_messages
    monkeypatch.setattr(registry,'MAX_NAMES',1)
    uc.mem_write(0x100,b'One\0');first=registry.register(uc,0x100)
    assert registry.register(uc,0x100)==first
    uc.mem_write(0x200,b'Two\0')
    with pytest.raises(UnsupportedAPI,match='budget exceeded'):registry.register(uc,0x200)
    assert len(registry.names)==1


def test_dispatch_obeys_stdcall_and_records_guest_only_evidence():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x100,b'Example\0');uc.mem_write(0x300,struct.pack('<II',0x12345678,0x100))
    value,esp=model.handler.apicall(0,'RegisterWindowMessageA',uc,0x300,False)
    assert value==0xc000 and esp==0x304
    assert uc.mem_read(esp,4)==struct.pack('<I',0x12345678)
    assert model.events[-1]['scope']=='isolated_guest_session'
