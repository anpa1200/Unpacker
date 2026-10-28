"""Benign generated ELF/ciphertext fixtures; no loader execution."""
from pathlib import Path
import pytest
pytest.importorskip('cryptography')
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms
try:from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:from cryptography.hazmat.primitives.ciphers.modes import CFB
from unpacker.unpackers.ezuri import _extract_ezuri,ezuri_layout
from unpacker.types import UnpackOptions
from unpacker.detector.pipeline import DetectorPipeline
from test_elf_notes import note_fixture,elf_header


def fixture_bytes(key_size=32):
    _,original=note_fixture();outer=bytearray(512);elf_header(outer,1,0x500100)
    import struct
    struct.pack_into('<IIQQQQQQ',outer,64,1,5,0,0x500000,0x500000,512,512,4096)
    outer[256:274]=b'main.runFromMemory'
    key=bytes(range(key_size));iv=bytes(range(16));encryptor=Cipher(algorithms.AES(key),CFB(iv)).encryptor()
    return bytes(outer)+key+iv+encryptor.update(original)+encryptor.finalize(),original


@pytest.mark.parametrize('key_size',[16,24,32])
def test_ezuri_static_recovers_exact_benign_elf_and_does_not_report_key(tmp_path,key_size):
    raw,original=fixture_bytes(key_size);sample=tmp_path/'input';sample.write_bytes(raw)
    result=_extract_ezuri(sample,tmp_path/'output',UnpackOptions(tmp_path))
    assert result.success and result.output_path.read_bytes()==original
    assert result.metadata['key_bytes']==key_size and 'key' not in result.metadata and 'iv' not in result.metadata
    assert result.metadata['authentication']=='format_has_no_authentication'
    detection=DetectorPipeline(use_native_upx=False)._detect_in_process(sample)
    assert detection.best_match.packer_id=='ezuri'


@pytest.mark.parametrize('mutation',['key','iv','payload','short','marker','budget'])
def test_ezuri_rejects_wrong_or_truncated_unsupported_trailers(tmp_path,mutation):
    raw,_=fixture_bytes();raw=bytearray(raw)
    if mutation=='key':raw[512]^=1
    if mutation=='iv':raw[544]^=1
    if mutation=='payload':raw[560]^=1
    if mutation=='short':raw=raw[:600]
    if mutation=='marker':raw[256:274]=bytes(18)
    if mutation=='budget':raw+=bytes(2*1024*1024)
    sample=tmp_path/'input';sample.write_bytes(raw)
    result=_extract_ezuri(sample,tmp_path/'output',UnpackOptions(tmp_path,max_output_size_mb=1))
    assert not result.success and result.status=='unsupported' and not (tmp_path/'output').exists()
