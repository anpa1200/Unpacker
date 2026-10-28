"""Synthetic ELF metadata; fixtures are never executed."""
import struct
from pathlib import Path
import pytest
from unpacker.elf_notes import note_payload
from unpacker.detector.pipeline import DetectorPipeline
from unpacker.types import UnpackOptions
from unpacker.unpackers.elf_note import _extract_note


def elf_header(data,phnum,entry):
    data[:16]=b'\x7fELF'+bytes([2,1,1])+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',data,16,2,62,1,entry,64,0,0,64,56,phnum,64,0,0)


def note_fixture():
    inner=bytearray(128);elf_header(inner,1,0x400078)
    struct.pack_into('<IIQQQQQQ',inner,64,1,5,0,0x400000,0x400000,len(inner),len(inner),4096)
    inner[120]=0xc3
    outer=bytearray(512);elf_header(outer,2,0x500100)
    struct.pack_into('<IIQQQQQQ',outer,64,1,5,0,0x500000,0x500000,512,512,4096)
    struct.pack_into('<IIQQQQQQ',outer,120,4,4,len(outer),0x500200,0x500200,len(inner),32,4)
    return outer+inner,bytes(inner)


def test_note_extraction_is_exact_and_needs_no_emulation_or_reference(tmp_path):
    raw,original=note_fixture();sample=tmp_path/'input';sample.write_bytes(raw)
    result=_extract_note(sample,tmp_path/'output',UnpackOptions(tmp_path))
    assert result.success and result.output_path.read_bytes()==original
    assert result.metadata['payload_offset']==512 and result.artifact_kind=='decompressed_file'
    assert result.output_path.stat().st_mode&0o777==0o600
    detection=DetectorPipeline(use_native_upx=False)._detect_in_process(sample)
    assert detection.best_match.packer_id=='elf_note'


@pytest.mark.parametrize('mutation',['trailing','overlap','segment_oob','wrong_note_size','no_exec_entry','bad_inner_count','inner_section_oob','oversize','not_elf'])
def test_malformed_ambiguous_or_unsupported_note_layouts_fail_closed(mutation):
    raw,_=note_fixture();limit=65536
    if mutation=='trailing':raw+=b'X'
    if mutation=='overlap':struct.pack_into('<Q',raw,128,0)
    if mutation=='segment_oob':struct.pack_into('<Q',raw,64+32,len(raw)+1)
    if mutation=='wrong_note_size':struct.pack_into('<Q',raw,120+32,2**32)
    if mutation=='no_exec_entry':struct.pack_into('<Q',raw,512+24,0xdeadbeef)
    if mutation=='bad_inner_count':struct.pack_into('<H',raw,512+56,65535)
    if mutation=='inner_section_oob':struct.pack_into('<Q',raw,512+40,120);struct.pack_into('<H',raw,512+60,1)
    if mutation=='oversize':limit=64
    if mutation=='not_elf':raw[512:516]=b'nope'
    with pytest.raises(ValueError):note_payload(bytes(raw),limit)
