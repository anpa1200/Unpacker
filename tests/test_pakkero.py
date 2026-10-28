"""Authenticated, bounded, reference-independent static extraction contracts."""
import base64,struct,zlib
from pathlib import Path
import pytest
from pakkero_fixture import elf,packed,go_padding
from unpacker.pakkero_format import upx_carrier,numeric_offsets,decode_payload,padding_size


@pytest.mark.parametrize('header_version',[13,14])
def test_unicode_offset_and_gcm_recover_exact_benign_elf_without_reference(header_version):
    data,launcher,payload=packed(numbers=(100001,100000),header_version=header_version)
    carrier,info=upx_carrier(data,1024*1024)
    assert carrier[124:128]==b'UPX!' and info['carrier_end']==548
    assert numeric_offsets(launcher,548,len(data))==[100000,100001]
    result,facts=decode_payload(data,launcher,len(carrier),1024*1024)
    assert result==payload and facts['numeric_candidates']==2
    assert facts['authentication']=='AES-GCM-128bit-tag' and not facts['self_prefix_payload']
    assert 'key' not in facts and 'nonce' not in facts


@pytest.mark.parametrize('position',[200,100000,-55,-70])
def test_modified_prefix_nonce_ciphertext_or_tag_never_authenticates(position):
    data,launcher,_=packed();data=bytearray(data);data[position]^=1
    with pytest.raises(ValueError,match='authenticated'):decode_payload(bytes(data),launcher,548,1024*1024)


@pytest.mark.parametrize('plaintext',[b'not-zlib',zlib.compress(b'not base64!'),zlib.compress(base64.b64encode(b'not ELF'))])
def test_authenticated_malformed_inner_formats_are_rejected(plaintext):
    data,launcher,_=packed(compressed_plaintext=plaintext)
    with pytest.raises(ValueError):decode_payload(data,launcher,548,1024*1024)


def test_authenticated_decompression_expansion_is_bounded():
    data,launcher,_=packed(compressed_plaintext=zlib.compress(b'A'*300000))
    with pytest.raises(ValueError,match='bounds'):decode_payload(data,launcher,548,100000)


def test_self_prefix_is_identified_without_reference_bytes():
    data,launcher,_=packed(self_prefix=True)
    payload,facts=decode_payload(data,launcher,548,1024*1024)
    assert payload==data[:100000] and facts['self_prefix_payload'] is True


def test_invalid_or_ambiguous_carrier_metadata_is_rejected():
    data,_,_=packed()
    for index in [5,18,130,131,543]:
        bad=bytearray(data);bad[index]^=1
        with pytest.raises(ValueError):upx_carrier(bytes(bad),1024*1024)
    bad=bytearray(data);bad[700:732]=bad[512:544]
    with pytest.raises(ValueError,match='unique'):upx_carrier(bytes(bad),1024*1024)


def test_go_string_pointers_must_be_mapped_and_candidate_budgets_apply(monkeypatch):
    import unpacker.pakkero_format as module
    data,launcher,_=packed(numbers=(100001,100000))
    monkeypatch.setattr(module,'MAX_CANDIDATES',1)
    with pytest.raises(ValueError,match='candidate budget'):numeric_offsets(launcher,548,len(data))
    monkeypatch.setattr(module,'MAX_HEADERS',1)
    with pytest.raises(ValueError,match='header budget'):numeric_offsets(launcher,548,len(data))
    bad=bytearray(launcher);struct.pack_into('<Q',bad,0x300,0xdeadbeef)
    monkeypatch.setattr(module,'MAX_HEADERS',4096);monkeypatch.setattr(module,'MAX_CANDIDATES',128)
    assert numeric_offsets(bytes(bad),548,len(data))==[100000]


@pytest.mark.parametrize('offset',[64,65,127,128,9999,100000,752299,10000000])
def test_padding_matches_independent_go_varint_model(offset):
    assert padding_size(offset)==go_padding(offset)


def extraction_fixture(tmp_path,monkeypatch,*,self_prefix=False,process_state='ok'):
    import unpacker.process as process
    import unpacker.unpackers.pakkero as module
    from unpacker.types import UnpackOptions
    data,launcher,payload=packed(self_prefix=self_prefix)
    sample=tmp_path/'fixture';sample.write_bytes(data);out=tmp_path/'out';out.mkdir()
    options=UnpackOptions(out,allow_emulation=False,extra={'reference':str(tmp_path/'must-not-be-read')})
    monkeypatch.setattr(module.shutil,'which',lambda name:'/known/upx')
    def decode(command,**kwargs):
        assert Path(command[-1]).read_bytes()[124:128]==b'UPX!'
        assert kwargs['start_new_session'] is False
        result={'returncode':0,'timed_out':False,'output_limit_exceeded':None,'stdout':'','stderr':''}
        if process_state=='ok':Path(command[3]).write_bytes(launcher)
        elif process_state=='timeout':result['timed_out']=True
        elif process_state=='quota':result['output_limit_exceeded']='aggregate test quota'
        else:result['returncode']=2
        return result
    monkeypatch.setattr(process,'run_command',decode)
    result=module._extract_pakkero(sample,out/'payload.bin',options)
    return result,payload,out


def test_static_extraction_writes_only_owned_nonexecutable_known_bytes(tmp_path,monkeypatch):
    result,payload,out=extraction_fixture(tmp_path,monkeypatch)
    assert result.success and result.output_path.read_bytes()==payload
    assert result.output_path.stat().st_mode&0o777==0o600
    assert list(out.iterdir())==[result.output_path]
    assert result.metadata['launcher_execution'] is False


def test_self_prefix_retains_review_artifact_and_cannot_claim_complete_recovery(tmp_path,monkeypatch):
    result,payload,out=extraction_fixture(tmp_path,monkeypatch,self_prefix=True)
    assert not result.success and result.status=='partial' and result.output_path.read_bytes()==payload
    assert result.metadata['self_prefix_payload'] is True and 'original application' in result.error
    assert list(out.iterdir())==[result.output_path]


@pytest.mark.parametrize('state,status',[('timeout','timeout'),('quota','resource_limit'),('error','unsupported')])
def test_vendor_failure_timeout_and_quota_never_leave_a_success_artifact(tmp_path,monkeypatch,state,status):
    result,_,out=extraction_fixture(tmp_path,monkeypatch,process_state=state)
    assert not result.success and result.status==status and result.output_path is None
    assert list(out.iterdir())==[]


def test_registry_selects_static_pakkero_instead_of_pe32_fallback(tmp_path):
    from unpacker.unpackers import get_unpacker_for
    from unpacker.unpackers.pakkero import PakkeroUnpacker
    assert isinstance(get_unpacker_for('pakkero',tmp_path/'fixture'),PakkeroUnpacker)
