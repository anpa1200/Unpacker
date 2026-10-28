"""Benign memory fixtures for descriptor-rooted resolved-import recovery."""
import struct
from types import SimpleNamespace as N
import pytest
from unpacker.image_snapshot import ImageSnapshot
from unpacker.pe_rebuilder.bound_imports import rebuild_bound_imports
from unpacker.pe_rebuilder.imports import retained_import_table
from unpacker.reconstruction import import_iat_consistency


def fixture():
    memory = bytearray(0x8000)
    struct.pack_into('<IIIII', memory, 0x1100, 0x1200, 0, 0, 0x1400, 0x1300)
    values = struct.pack('<III', 0x701000, 0x702000, 0)
    for address in [0x1200, 0x1300, 0x1500]:
        memory[address:address + len(values)] = values
    memory[0x1400:0x140d] = b'KERNEL32.dll\0'
    section = N(VirtualAddress=0x1000, VirtualSize=0x2000, SizeOfRawData=0x2000)
    observed = {'KERNEL32.dll#0': [('ExitProcess', 0x701000), ('ordinal/name/7', 0x702000)],
                'kernel32#0': [('VirtualProtect', 0x703000)]}
    return memory, [section], observed


def recover(memory, sections, observed):
    cpu = N(mem_read=lambda address, count: memory[address-0x400000:address-0x400000+count])
    snapshot = ImageSnapshot(cpu, 0x400000, len(memory), 32768)
    before = bytes(memory)
    result = rebuild_bound_imports(snapshot, 0x400000, len(memory), sections, observed, 0x1100)
    assert memory == before
    return snapshot, result


def test_declared_iat_beats_duplicate_resolved_arrays_without_reference():
    memory, sections, observed = fixture()
    snapshot, facts = recover(memory, sections, observed)
    assert facts['iat_rvas'] == [0x1300] and facts['symbols'] == 2
    assert facts['unrepresented_observed_modules'] == ['kernel32']
    assert snapshot.data[0x1200:0x120c] == memory[0x1200:0x120c]
    assert snapshot.data[0x1500:0x150c] == memory[0x1500:0x150c]
    pe = N(OPTIONAL_HEADER=N(Magic=0x10b), FILE_HEADER=N(Machine=0x14c),
           get_data=lambda rva, count: bytes(snapshot.data[rva:rva+count]))
    all_sections = [N(VirtualAddress=0x1000, Misc_VirtualSize=0x7000, SizeOfRawData=0x7000)]
    table = retained_import_table(pe, facts['rva'], all_sections)
    assert table['descriptors'][0]['symbols'] == ['ExitProcess', '#7']
    desc = table['descriptors'][0]
    pe.DIRECTORY_ENTRY_IMPORT = [N(struct=N(FirstThunk=desc['iat_rva'], OriginalFirstThunk=desc['lookup_rva']),
                                  imports=[N(), N()])]
    assert import_iat_consistency(pe)['passed']
    assert pe.get_data(0x1308, 4) == bytes(4)


@pytest.mark.parametrize('mutation', ['ambiguous', 'missing', 'mismatch', 'terminator',
                                    'unaligned', 'timestamp', 'module', 'overlap',
                                    'workspace', 'omitted_binding', 'directory_alias'])
def test_invalid_or_ambiguous_bound_tables_never_patch_snapshot(mutation):
    memory, sections, observed = fixture()
    if mutation == 'ambiguous': observed['KERNEL32.dll#0'].append(('OtherName', 0x701000))
    if mutation == 'missing': observed['KERNEL32.dll#0'].pop()
    if mutation == 'mismatch': struct.pack_into('<I', memory, 0x1200, 0x999999)
    if mutation == 'terminator':
        struct.pack_into('<I', memory, 0x1208, 0x999999)
        struct.pack_into('<I', memory, 0x1308, 0x999999)
    if mutation == 'unaligned': struct.pack_into('<I', memory, 0x1110, 0x1301)
    if mutation == 'timestamp': struct.pack_into('<I', memory, 0x1104, 1)
    if mutation == 'module': memory[0x1400] = 0xff
    if mutation == 'overlap': sections.append(sections[0])
    if mutation == 'workspace': memory[0x3000:] = b'X' * (len(memory)-0x3000)
    if mutation == 'omitted_binding': observed['KERNEL32.dll#0'].append(('Unrepresented', 0x703000))
    if mutation == 'directory_alias': struct.pack_into('<I', memory, 0x1110, 0x1100)
    cpu = N(mem_read=lambda address, count: memory[address-0x400000:address-0x400000+count])
    snapshot = ImageSnapshot(cpu, 0x400000, len(memory), 32768)
    before = bytes(snapshot.data)
    with pytest.raises((ValueError, UnicodeError)):
        rebuild_bound_imports(snapshot, 0x400000, len(memory), sections, observed, 0x1100)
    assert snapshot.data == before


def test_lookup_absent_is_supported_only_with_correlated_terminated_iat():
    memory, sections, observed = fixture()
    struct.pack_into('<I', memory, 0x1100, 0)
    snapshot, facts = recover(memory, sections, observed)
    assert facts['iat_rvas'] == [0x1300]


def test_complete_application_epoch_is_separate_from_loader_queries_on_same_real_module():
    memory,sections,observed=fixture()
    observed['KERNEL32.dll#1']=[('LoaderOnly',0x703000)]
    snapshot,facts=recover(memory,sections,observed)
    assert facts['symbols']==2 and facts['matched_observation_epochs']['kernel32.dll']==['KERNEL32.dll#0']
    assert 'KERNEL32.dll#1' in facts['unrepresented_observed_epochs']


def test_incomplete_subset_of_an_epoch_cannot_be_promoted_as_a_complete_table():
    memory,sections,observed=fixture()
    observed['KERNEL32.dll#0'].append(('LoaderOnly',0x703000))
    observed['KERNEL32.dll#1']=[('Irrelevant',0x704000)]
    with pytest.raises(ValueError,match='omits observed'):recover(memory,sections,observed)


def test_invalid_directory_and_bounds_are_rejected():
    memory, sections, observed = fixture()
    cpu = N(mem_read=lambda address, count: memory[address-0x400000:address-0x400000+count])
    for directory in [0, 0x1101, 0x9000]:
        snapshot = ImageSnapshot(cpu, 0x400000, len(memory), 32768)
        with pytest.raises(ValueError):
            rebuild_bound_imports(snapshot, 0x400000, len(memory), sections, observed, directory)


def test_observation_budget_and_truncated_reads_are_rejected():
    memory, sections, observed = fixture()
    cpu = N(mem_read=lambda address, count: memory[address-0x400000:address-0x400000+count])
    snapshot = ImageSnapshot(cpu, 0x400000, len(memory), 32768)
    observed['extra'] = [('BenignName', 0x1234)] * 4097
    with pytest.raises(ValueError, match='excessive'):
        rebuild_bound_imports(snapshot, 0x400000, len(memory), sections, observed, 0x1100)
    with pytest.raises(ValueError, match='Truncated'):
        rebuild_bound_imports(N(mem_read=lambda address, count: b''), 0x400000,
                              len(memory), sections, {}, 0x1100)
