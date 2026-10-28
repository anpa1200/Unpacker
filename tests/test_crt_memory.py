"""Generated allocation data only; all pointers refer to the test guest memory."""
import struct
import pytest
from test_winapi_model import fixture_model
from unpacker.winapi_model import UnsupportedAPI


def test_crt_zero_allocation_null_free_and_ownership():
    model, uc, _ = fixture_model()
    crt = model.crt_memory
    zero = crt.malloc(uc, 0)
    assert zero and zero % 8 == 0 and crt.allocations[zero] == 0
    assert crt.free(uc, 0) is None
    other = model.global_alloc(uc, 0, 16)
    with pytest.raises(UnsupportedAPI):
        crt.free(uc, other)
    assert other in model.globals
    crt.free(uc, zero)
    with pytest.raises(UnsupportedAPI):
        crt.free(uc, zero)


def test_calloc_zeroes_and_rejects_size_t_overflow_with_guest_errno():
    model, uc, _ = fixture_model()
    crt = model.crt_memory
    address = crt.calloc(uc, 4, 8)
    assert address and uc.mem_read(address, 32) == bytes(32)
    assert crt.calloc(uc, 0xffffffff, 2) == 0
    assert uc.mem_read(model.crt_cells['errno'], 4) == struct.pack('<I', 12)
    assert address in crt.allocations
    assert crt.calloc(uc, 0, 99) != 0


def test_realloc_preserves_prefix_failure_ownership_and_zero_free_contract():
    model, uc, _ = fixture_model()
    crt = model.crt_memory
    original = crt.realloc(uc, 0, 16)
    uc.mem_write(original, b'0123456789ABCDEF')
    assert crt.realloc(uc, original, model.limit+1) == 0
    assert original in crt.allocations and uc.mem_read(original, 16) == b'0123456789ABCDEF'
    enlarged = crt.realloc(uc, original, 8192)
    assert enlarged != original and original not in crt.allocations
    assert uc.mem_read(enlarged, 16) == b'0123456789ABCDEF'
    assert crt.realloc(uc, enlarged, 8) == enlarged
    assert crt.realloc(uc, enlarged, 0) == 0 and enlarged not in crt.allocations
    with pytest.raises(UnsupportedAPI):
        crt.realloc(uc, enlarged, 8)


def test_new_handler_failure_stops_explicitly_and_cdecl_arguments_are_preserved():
    model, uc, _ = fixture_model()
    model.install({})
    uc.mem_write(0x200, struct.pack('<II', 0x12345678, 12))
    address, esp = model.handler.apicall(0, 'malloc', uc, 0x200, False)
    assert address and esp == 0x200
    uc.mem_write(0x204, struct.pack('<I', address))
    assert model.handler.apicall(0, 'free', uc, 0x200, False) == (None, 0x200)
    model.crt_startup.newmode = 1
    with pytest.raises(UnsupportedAPI, match='new-handler'):
        model.crt_memory.malloc(uc, model.limit+1)


def test_exhausted_quota_returns_null_without_destroying_live_crt_data():
    model, uc, _ = fixture_model()
    crt = model.crt_memory
    address = crt.malloc(uc, model.limit-4096)
    assert address
    uc.mem_write(address, b'owned')
    assert crt.malloc(uc, 1) == 0 and uc.mem_read(address, 5) == b'owned'
    assert sum(model.globals.values()) == model.limit
