"""Benign legacy MSVCRT state tests, using guest memory only."""
import struct
import pytest
from test_winapi_model import fixture_model
from unpacker.winapi_model import UnsupportedAPI


def test_c_locale_is_process_owned_stable_and_initialized_with_unsigned_sentinels():
    model, uc, _ = fixture_model()
    crt = model.crt_startup
    pointer = crt.localeconv(uc)
    fields = struct.unpack('<10I', uc.mem_read(pointer, 40))
    assert uc.mem_read(fields[0], 2) == b'.\0'
    assert all(uc.mem_read(p, 1) == b'\0' for p in fields[1:])
    assert uc.mem_read(pointer+40, 8) == bytes([127])*8
    assert crt.initialize_locale(uc) == 0 and crt.localeconv(uc) == pointer
    assert uc.mem_read(pointer+40, 8) == bytes([255])*8
    assert crt.initialize_locale(uc) == 0 and crt.localeconv(uc) == pointer
    other, _, _ = fixture_model()
    assert not other.crt_startup.locale_initialized


def test_getmainargs_provides_one_virtual_argument_and_empty_guest_environment():
    model, uc, _ = fixture_model()
    crt = model.crt_startup
    uc.mem_write(0x300, struct.pack('<I', 1))
    for wildcard in [0, 1]:
        assert crt.getmainargs(uc, 0x200, 0x204, 0x208, wildcard, 0x300) == 0
        count, argv, env = struct.unpack('<III', uc.mem_read(0x200, 12))
        assert count == 1 and uc.mem_read(env, 4) == bytes(4)
        arg, end = struct.unpack('<II', uc.mem_read(argv, 8))
        assert not end and uc.mem_read(arg, len(model.PATH)+1) == model.PATH+b'\0'
        assert crt.newmode == 1


@pytest.mark.parametrize('mutation', ['null', 'mode', 'wildcard'])
def test_getmainargs_rejects_unmodeled_settings(mutation):
    model, uc, stops = fixture_model()
    if mutation == 'mode':
        uc.mem_write(0x300, struct.pack('<I', 99))
    with pytest.raises(UnsupportedAPI):
        model.crt_startup.getmainargs(uc, 0 if mutation == 'null' else 0x200,
                                     0x204, 0x208, 2 if mutation == 'wildcard' else 0, 0x300)
    assert stops and model.crt_startup.arguments is None


def test_crt_startup_dispatch_preserves_cdecl_stack_arguments():
    model, uc, _ = fixture_model()
    model.install({})
    stack = struct.pack('<6I', 0x12345678, 0x200, 0x204, 0x208, 0, 0x300)
    uc.mem_write(0x400, stack)
    assert model.handler.apicall(0, '__getmainargs', uc, 0x400, False) == (0, 0x400)
    assert uc.mem_read(0x400, len(stack)) == stack
    assert model.handler.apicall(0, '__lconv_init', uc, 0x400, False) == (0, 0x400)


def test_exit_registration_retains_order_without_running_guest_or_host_callbacks():
    model, uc, stops = fixture_model()
    uc.mem_regions = lambda: [(0x400000, 0x40ffff, 5), (0x500000, 0x50ffff, 3)]
    crt = model.crt_startup
    assert crt.register_exit(uc, 0x401000) == 0x401000
    assert crt.register_exit(uc, 0x402000) == 0x402000
    assert crt.exit_callbacks == [0x401000, 0x402000] and not stops
    with pytest.raises(UnsupportedAPI, match='executable'):
        crt.register_exit(uc, 0x501000)
    crt.exit_callbacks = [0x401000]*1024
    assert crt.register_exit(uc, 0x402000) == 0 and len(crt.exit_callbacks) == 1024
