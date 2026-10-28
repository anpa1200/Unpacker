"""Benign reproductions of the backend's prefix-only/ambiguous IAT selection."""
import struct
from types import SimpleNamespace as N
import pytest
from unpacker.pe_rebuilder.iat_search import find_unique_iat


VALUES=[0x104000,0x104008,0x104010]
pack=lambda values:struct.pack('<'+'I'*len(values),*values)


def test_unique_whole_sequence_requires_alignment_and_zero_terminator():
    memory=b'x'*16+pack(VALUES+[0])+b'x'*16
    assert find_unique_iat(memory,VALUES)=={'rva':16,'reason':'unique_complete_terminated_sequence','candidates_checked':1}


def test_matching_first_pair_does_not_authorize_overwriting_a_different_tail():
    memory=b'x'*16+pack(VALUES[:2]+[0x999999,0])+b'x'*16
    before=memory
    assert find_unique_iat(memory,VALUES)['rva'] is None
    assert memory==before


@pytest.mark.parametrize('tail',[b'',b'\0\0',pack([0x104018])])
def test_truncated_or_nonzero_terminator_is_rejected(tail):
    assert find_unique_iat(b'x'*16+pack(VALUES)+tail,VALUES)['rva'] is None


def test_mirrored_complete_arrays_are_ambiguous_without_descriptor_provenance():
    memory=pack(VALUES+[0])+pack(VALUES+[0])
    facts=find_unique_iat(memory,VALUES)
    assert facts['rva'] is None and facts['reason']=='ambiguous_complete_sequences'


def test_unaligned_whole_array_is_not_selected():
    assert find_unique_iat(b'x'+pack(VALUES+[0]),VALUES)['rva'] is None


def test_prefix_decoy_is_ignored_when_one_complete_sequence_exists():
    memory=pack(VALUES[:2]+[0x999999,0])+pack(VALUES+[0])
    assert find_unique_iat(memory,VALUES)['rva']==16


@pytest.mark.parametrize('values',[[],[0],[-1],[2**32],[True],[1.5],['1'],[1]*4097])
def test_invalid_observation_sequences_fail_explicitly(values):
    with pytest.raises(ValueError):find_unique_iat(b'x'*64,values)


def test_repetitive_candidate_search_is_bounded():
    facts=find_unique_iat(pack([0x104000]*200),[0x104000],max_candidates=8)
    assert facts=={'rva':None,'reason':'candidate_budget_exceeded','candidates_checked':8}


def test_memory_budget_and_truncated_backend_reads_are_rejected(monkeypatch):
    import unpacker.pe_rebuilder.iat_search as module
    monkeypatch.setattr(module,'MAX_IMAGE_BYTES',32)
    with pytest.raises(ValueError):find_unique_iat(b'x'*33,VALUES)
    from unpacker.unpackers._unipacker_shared import _strict_find_iat
    with pytest.raises(ValueError,match='Truncated'):_strict_find_iat(None,N(mem_read=lambda a,n:b''),0,16,VALUES,'benign.dll')


def test_backend_wrapper_records_bounded_facts_without_modifying_guest_bytes(monkeypatch):
    import unpacker.unpackers._unipacker_shared as shared
    state={};monkeypatch.setattr(shared,'_DUMP_STATE',state)
    memory=b'x'*16+pack(VALUES+[0])+b'x'*16
    uc=N(mem_read=lambda a,n:memory[a-0x400000:a-0x400000+n])
    for _ in range(40):assert shared._strict_find_iat(None,uc,0x400000,len(memory),VALUES,'benign.dll')==16
    assert state['iat_search_count']==40 and len(state['iat_searches'])==32
    assert state['iat_searches'][0]['reason']=='unique_complete_terminated_sequence'
