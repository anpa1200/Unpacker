"""Benign PEtite loader-section boundaries; no specimen execution."""
from types import SimpleNamespace as N

import pytest

from unpacker.unpackers._unipacker_shared import _configure_petite_unpacker


def fixture():
    return N(unpacker=N(name='PEtite',allowed_addr_ranges=[(0x40710b,0x408795)]),
             opt_header=N(ImageBase=0x400000,AddressOfEntryPoint=0x710b),
             sections=[N(VirtualAddress=0x1000,VirtualSize=0x3000),
                       N(VirtualAddress=0x7000,VirtualSize=0x1795)])


def test_earlier_loader_instruction_is_inside_range_and_end_is_exclusive():
    sample=fixture()
    lower,upper=_configure_petite_unpacker(sample)
    assert lower<=0x4070ce<=upper
    assert (lower,upper)==(0x407000,0x408794)
    assert not lower<=0x401000<=upper
    assert not lower<=0x408795<=upper


def test_other_packers_keep_their_existing_ranges():
    sample=fixture();sample.unpacker.name='MPRESS'
    before=list(sample.unpacker.allowed_addr_ranges)
    assert _configure_petite_unpacker(sample) is None
    assert sample.unpacker.allowed_addr_ranges==before


@pytest.mark.parametrize('mutation',['missing','overlapping','overflow','oversize'])
def test_ambiguous_or_unbounded_loader_sections_fail(mutation,monkeypatch):
    import unpacker.unpackers._unipacker_shared as shared
    monkeypatch.setattr(shared,'_MAX_DUMP_BYTES',32*1024*1024)
    sample=fixture()
    if mutation=='missing':sample.opt_header.AddressOfEntryPoint=0x5000
    if mutation=='overlapping':sample.sections.append(sample.sections[-1])
    if mutation=='overflow':sample.opt_header.ImageBase=0xffffc000
    if mutation=='oversize':sample.sections[-1].VirtualSize=33*1024*1024
    with pytest.raises(ValueError):_configure_petite_unpacker(sample)
