"""Generated PE headers and sparse guest bytes; no DLL or sample is executed."""
import struct
from types import SimpleNamespace as N
import pytest
from unpacker.loader_lists import install_loader_lists


class SparseMemory:
    def __init__(self):
        self.data = {}
        self.regions = [(0x200000, 0x205fff, 3)] + [(p, p+0x1fff, 7) for p in [0x400000, 0x77400000, 0x755d0000, 0x73d00000]]
    def mem_regions(self):
        return self.regions
    def mem_read(self, address, size):
        assert any(lo <= address and address+size-1 <= hi for lo, hi, _ in self.regions)
        return bytes(self.data.get(address+i, 0) for i in range(size))
    def mem_write(self, address, payload):
        assert any(lo <= address and address+len(payload)-1 <= hi for lo, hi, _ in self.regions)
        self.data.update({address+i: value for i, value in enumerate(payload)})


def fixture():
    uc = SparseMemory()
    for base in [0x400000, 0x77400000, 0x755d0000, 0x73d00000]:
        header = bytearray(512)
        header[:2] = b'MZ'
        struct.pack_into('<I', header, 60, 128)
        header[128:132] = b'PE\0\0'
        struct.pack_into('<H', header, 132, 0x14c)
        struct.pack_into('<H', header, 152, 0x10b)
        struct.pack_into('<I', header, 168, 0x1000)
        struct.pack_into('<I', header, 208, 0x2000)
        uc.mem_write(base, header)
    return N(uc=uc, PEB_BASE=0x201000, sample=N(BASE_ADDR=0x400000))


def walk(uc, head, offset):
    current, last = struct.unpack('<II', uc.mem_read(head, 8))
    result = []
    previous = head
    while current != head:
        following, backlink = struct.unpack('<II', uc.mem_read(current, 8))
        assert backlink == previous and len(result) < 5
        result.append(current-offset)
        previous, current = current, following
    assert previous == last
    return result


def test_loader_lists_are_complete_rings_with_distinct_embedded_links_and_utf16_names():
    engine = fixture()
    uc = engine.uc
    result = install_loader_lists(engine)
    assert result['scope'] == 'already_mapped_modules_only'
    ldr = struct.unpack('<I', uc.mem_read(engine.PEB_BASE+12, 4))[0]
    loaded = walk(uc, ldr+0x0c, 0)
    assert loaded == walk(uc, ldr+0x14, 8)
    assert walk(uc, ldr+0x1c, 16) == [loaded[1], loaded[3], loaded[2]]
    names = []
    for entry in loaded:
        length, maximum, pointer = struct.unpack('<HHI', uc.mem_read(entry+0x2c, 8))
        assert maximum == length+2 and length > 0
        assert uc.mem_read(pointer+length, 2) == bytes(2)
        names.append(uc.mem_read(pointer, length).decode('utf-16le'))
        base, start, size = struct.unpack('<III', uc.mem_read(entry+0x18, 12))
        assert start == base+0x1000 and size == 0x2000
    assert names == ['sample.bin', 'ntdll.dll', 'kernel32.dll', 'KernelBase.dll']


@pytest.mark.parametrize('mutation', ['header', 'offset', 'size', 'mapping', 'metadata_mapping'])
def test_invalid_loader_modules_do_not_partially_write_guest_process_metadata(mutation):
    engine = fixture()
    uc = engine.uc
    if mutation == 'header':
        uc.mem_write(0x77400000, b'XX')
    if mutation == 'offset':
        uc.mem_write(0x77400000+60, struct.pack('<I', 65536))
    if mutation == 'size':
        uc.mem_write(0x77400000+208, struct.pack('<I', 0x10000000))
    if mutation == 'mapping':
        uc.mem_write(0x77400000+208, struct.pack('<I', 0x3000))
        uc.mem_write(0x77400000+168, struct.pack('<I', 0x2500))
    if mutation == 'metadata_mapping':
        uc.regions[0] = (0x200000, 0x203fff, 3)
    before = dict(uc.data)
    with pytest.raises(ValueError):
        install_loader_lists(engine)
    assert uc.data == before
