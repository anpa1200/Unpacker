"""Generated memory-only import skeletons; no executable fixtures are run."""
import struct
from types import SimpleNamespace as N

import pytest

from unpacker.pe_rebuilder.erased_names import find_erased_import_names


def fixture():
    memory = bytearray(8192)
    struct.pack_into('<IIIII', memory, 0x1000, 0x1100, 0xffffffff, 0xffffffff, 0x1200, 0x1140)
    struct.pack_into('<III', memory, 0x1100, 0x1300, 0x80000007, 0)
    struct.pack_into('<III', memory, 0x1140, 0x500001, 0x500002, 0)
    memory[0x1200:0x120d] = b'KERNEL32.dll\0'
    memory[0x1300:0x1302] = b'\x23\x01'  # Retained hint, erased name.
    sections = [N(VirtualAddress=0x1000, VirtualSize=4096, SizeOfRawData=4096)]
    observed = {'kernel32.dll#0': [('ExitProcess', 0x500001), ('ord/name/7', 0x500002)],
                'user32.dll#0': [('StubOnly', 0x600001)]}
    return memory, sections, observed


def test_erased_names_require_live_module_address_and_preserve_hints():
    memory, sections, observed = fixture()
    before = bytes(memory)
    table = find_erased_import_names(memory, sections, observed)
    assert table['symbol_count'] == 2 and table['descriptor_bytes'] == 40
    assert table['name_patches'] == [(0x1302, b'ExitProcess\0')]
    assert table['descriptors'][0]['symbols'] == ['ExitProcess', '#7']
    assert bytes(memory) == before  # Planning never changes the caller's bytes.


@pytest.mark.parametrize('mutation', [
    'unknown_address', 'ambiguous_address', 'different_module', 'not_erased',
    'partial_erasure', 'ordinal', 'iat_end', 'empty', 'bounds', 'overlap',
    'ambiguous_table', 'no_lookup', 'no_erasure',
])
def test_erased_name_recovery_refuses_missing_ambiguous_or_unsafe_evidence(mutation):
    memory, sections, observed = fixture()
    if mutation == 'unknown_address':
        struct.pack_into('<I', memory, 0x1140, 0x123456)
    if mutation == 'ambiguous_address':
        observed['kernel32.dll#0'].append(('Different', 0x500001))
    if mutation == 'different_module':
        observed['other.dll'] = observed.pop('kernel32.dll#0')
    if mutation == 'not_erased':
        memory[0x1302:0x1306] = b'evil'
    if mutation == 'partial_erasure':
        memory[0x1309] = 1
    if mutation == 'ordinal':
        struct.pack_into('<I', memory, 0x1104, 0x80000008)
    if mutation == 'iat_end':
        struct.pack_into('<I', memory, 0x1148, 0x123456)
    if mutation == 'empty':
        memory[0x1000:0x1014] = bytes(20)
    if mutation == 'bounds':
        sections[0].SizeOfRawData = sections[0].VirtualSize = 0x200
    if mutation == 'overlap':
        # Would replace the hint/name area across a live lookup terminator.
        struct.pack_into('<I', memory, 0x1100, 0x1108)
    if mutation == 'ambiguous_table':
        memory[0x1400:0x1428] = memory[0x1000:0x1028]
    if mutation == 'no_lookup':
        struct.pack_into('<I', memory, 0x1000, 0)
    if mutation == 'no_erasure':
        memory[0x1302:0x130e] = b'ExitProcess\0'
    assert find_erased_import_names(memory, sections, observed) is None


def test_intact_and_erased_names_can_share_a_corroborated_table():
    memory, sections, observed = fixture()
    struct.pack_into('<III', memory, 0x1100, 0x1300, 0x1340, 0)
    memory[0x1342:0x134c] = b'HeapAlloc\0'
    observed['kernel32.dll#0'][1] = ('HeapAlloc', 0x500002)
    table = find_erased_import_names(memory, sections, observed)
    assert table['name_patches'] == [(0x1302, b'ExitProcess\0')]
    assert table['descriptors'][0]['symbols'] == ['ExitProcess', 'HeapAlloc']
