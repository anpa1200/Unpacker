"""Reconstruction isolation tests use benign memory and metadata only."""
from types import SimpleNamespace as N
import pytest
from unpacker.image_snapshot import ImageSnapshot,handoff_rejection


def test_reconstruction_writes_never_mutate_live_guest_image():
    source=bytearray(b'benign guest memory')
    cpu=N(mem_read=lambda address,size:source[address-0x1000:address-0x1000+size],reg_read=lambda register:17,mem_regions=lambda:[(0x1000,0x1fff,7)])
    snapshot=ImageSnapshot(cpu,0x1000,len(source),1024)
    snapshot.mem_write(0x1000,b'STAGED')
    assert source==b'benign guest memory' and snapshot.mem_read(0x1000,6)==b'STAGED'
    assert snapshot.reg_read(1)==17 and snapshot.mem_regions()==[(0x1000,0x1fff,7)]
    for address,size in [(0x0fff,1),(0x1000,100),(0x1000,-1)]:
        with pytest.raises(ValueError):snapshot.mem_read(address,size)
    with pytest.raises(ValueError):snapshot.mem_write(0x1000,b'X'*100)
    with pytest.raises(ValueError):ImageSnapshot(cpu,0x1000,len(source),1)


def test_invalid_generic_candidate_is_rejected_without_original(tmp_path):
    candidate=tmp_path/'candidate'
    assert handoff_rejection(candidate)
    candidate.write_bytes(b'benign malformed image')
    assert handoff_rejection(candidate)=='Candidate PE headers are invalid'


def test_snapshot_reads_support_upstream_ctypes_without_aliasing_source():
    import ctypes
    original=bytearray(b'ABCD')
    cpu=N(mem_read=lambda address,size:original[:size],reg_read=lambda register:0,mem_regions=lambda:[])
    snapshot=ImageSnapshot(cpu,0,4,4);read=snapshot.mem_read(0,4)
    value=ctypes.c_uint32.from_buffer(read);value.value=0
    assert original==b'ABCD' and snapshot.mem_read(0,4)==b'ABCD'


def test_iat_failure_details_are_bounded_without_changing_gate_result():
    from unpacker.reconstruction import import_iat_consistency
    descriptor=N(struct=N(FirstThunk=0x2000,OriginalFirstThunk=0x3000),imports=[N() for _ in range(200)])
    pe=N(OPTIONAL_HEADER=N(Magic=0x10b),DIRECTORY_ENTRY_IMPORT=[descriptor],
         get_data=lambda rva,count:(b'\x01\0\0\0' if rva<0x3000 else b'\x02\0\0\0'))
    ordinary=import_iat_consistency(pe);detailed=import_iat_consistency(pe,include_details=True)
    assert not ordinary['passed'] and not detailed['passed']
    assert ordinary['checked_symbols']==detailed['checked_symbols']==200
    assert ordinary['inconsistent_iat_rvas']==detailed['inconsistent_iat_rvas']
    assert len(detailed['details'])==16 and 'details' not in ordinary
