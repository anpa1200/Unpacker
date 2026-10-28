"""Metadata-only hot-path checks, including layout replacement and raw edges."""
from types import SimpleNamespace as N
import pytest
from unpacker.unpackers._unipacker_shared import _generic_handoff_eligible


def fixture(immutable=True):
    rows=[(0x401000,0x2000,116),(0x413000,0x6000,0x4800)]
    return N(_handoff_image_sections=tuple(rows) if immutable else rows,_handoff_loader_sections=set())


@pytest.mark.parametrize('resolved',[False,True])
@pytest.mark.parametrize('offset,expected',[(0,False),(115,False),(116,True),(0x1fff,True)])
def test_cached_loader_keeps_the_same_raw_boundary(resolved,offset,expected):
    sample=fixture();assert not _generic_handoff_eligible(sample,0x401000,[],False)
    assert _generic_handoff_eligible(sample,0x401000+offset,[],resolved) is expected


def test_guest_layout_replacement_invalidates_cached_raw_extent():
    sample=fixture();assert not _generic_handoff_eligible(sample,0x401000,[],False)
    assert not _generic_handoff_eligible(sample,0x401040,[],True)
    sample._handoff_image_sections=((0x401000,0x2000,32),)
    assert _generic_handoff_eligible(sample,0x401040,[],True)


def test_section_change_and_external_address_never_reuse_wrong_section():
    sample=fixture();_generic_handoff_eligible(sample,0x401000,[],False)
    assert not _generic_handoff_eligible(sample,0x413000,[],False)
    assert _generic_handoff_eligible(sample,0x417800,[],True)
    assert not _generic_handoff_eligible(sample,0x200000,[],True)


def test_mutable_compatibility_layout_is_not_cached():
    sample=fixture(False);_generic_handoff_eligible(sample,0x401000,[],False)
    assert not hasattr(sample,'_handoff_cached_loader')
    sample._handoff_image_sections[0]=(0x401000,0x2000,32)
    assert _generic_handoff_eligible(sample,0x401040,[],True)


def test_cache_does_not_skip_initial_write_or_resolution_classification():
    sample=fixture()
    assert _generic_handoff_eligible(sample,0x401040,[(0x401000,0x401100)],False)
    assert not sample._handoff_loader_sections
    assert _generic_handoff_eligible(sample,0x401040,[],True)
    assert not sample._handoff_loader_sections
    assert not _generic_handoff_eligible(sample,0x401040,[],False)
    assert sample._handoff_loader_sections=={0x401000}
