"""Adversarial report contracts and benign input snapshots; no sample execution."""
import copy,hashlib,json,os
from pathlib import Path
import pytest
from unpacker.report_integrity import snapshot_input,load_report,check_report,accepted_recovery,verify_artifacts

def fixture(tmp_path):
    data=b'benign candidate';p=tmp_path/'artifacts/attempt/output.bin';p.parent.mkdir(parents=True);p.write_bytes(data)
    source=hashlib.sha256(b'benign source').hexdigest();output=hashlib.sha256(data).hexdigest()
    result={'success':True,'output_path':'/out/artifacts/attempt/output.bin','metadata':{'output_sha256':output,'input_sha256':source},'validation_status':'structurally_valid','warnings':[],'artifact_kind':'decompressed_file'}
    layer={'input_sha256':source,'output_sha256':output,'output_path':result['output_path'],'unpack_result':result}
    return {'sample_path':'/input.bin','status':'extracted','layers':[layer],'final_path':result['output_path']},source,p

def test_snapshot_is_regular_capped_and_independent_of_later_source_change(tmp_path):
    original=tmp_path/'source';original.write_bytes(b'original');copy=tmp_path/'snapshot'
    assert snapshot_input(original,copy)==hashlib.sha256(b'original').hexdigest()
    original.write_bytes(b'replaced');assert copy.read_bytes()==b'original' and copy.stat().st_mode&0o777==0o600
    with pytest.raises(ValueError):snapshot_input(original,tmp_path/'too-small',1)
    link=tmp_path/'link';link.symlink_to(original)
    with pytest.raises(OSError):snapshot_input(link,tmp_path/'linked')
    fifo=tmp_path/'pipe';os.mkfifo(fifo)
    with pytest.raises(ValueError):snapshot_input(fifo,tmp_path/'fifo-copy')

@pytest.mark.parametrize('raw',['{"status":"failed","status":"extracted"}','{"status":NaN}','{"v":Infinity}'])
def test_report_rejects_duplicate_and_nonfinite_fields(tmp_path,raw):
    p=tmp_path/'report';p.write_text(raw)
    with pytest.raises(ValueError):load_report(p)

@pytest.mark.parametrize('mutation',[
    lambda r:r['layers'][0].update(input_sha256='0'*64),
    lambda r:r['layers'][0].update(output_sha256='0'*64),
    lambda r:r.update(final_path='/etc/passwd'),
    lambda r:r['layers'][0]['unpack_result'].update(output_path='/out/artifacts/../report.json'),
    lambda r:r['layers'][0]['unpack_result'].update(success=False),
    lambda r:r.update(status='invented_success'),
])
def test_report_rejects_hash_path_and_status_contradictions(tmp_path,mutation):
    report,source,_=fixture(tmp_path);mutation(report)
    with pytest.raises(ValueError):check_report(report,tmp_path,source)

def test_report_validates_actual_bytes_and_rejects_symlink(tmp_path):
    report,source,p=fixture(tmp_path);assert len(check_report(report,tmp_path,source))==1
    p.write_bytes(b'changed')
    with pytest.raises(ValueError):check_report(report,tmp_path,source)
    p.unlink();p.symlink_to(tmp_path/'other');(tmp_path/'other').write_bytes(b'benign candidate')
    with pytest.raises(ValueError):check_report(report,tmp_path,source)

@pytest.mark.parametrize('status',['partial','extracted_unverified','extracted_with_residual_evidence','no_packing_evidence','unsupported'])
def test_machine_acceptance_never_promotes_completion_or_partial(tmp_path,status):
    report,_,_=fixture(tmp_path);report['status']=status;assert not accepted_recovery(report)

def test_separate_validation_rejects_worker_claim_and_preserves_partial(tmp_path,monkeypatch):
    import unpacker.process as process
    import unpacker.sandbox_cli as sandbox
    report,source,p=fixture(tmp_path);artifacts=check_report(report,tmp_path,source);seen={}
    def build(candidate,output,args,**kwargs):seen.update(kwargs);return ['benign-validator']
    monkeypatch.setattr(sandbox,'build_command',build)
    monkeypatch.setattr(process,'run_command',lambda *a,**k:{'returncode':0,'timed_out':False,'stdout':json.dumps(['partial',{'output_sha256':report['layers'][0]['output_sha256'],'reason':'Known-original mismatch'}])})
    receipt=verify_artifacts(report,artifacts,tmp_path/'source',tmp_path/'reference',tmp_path,float('inf'))
    assert report['status']=='partial' and not receipt['accepted_recovery']
    assert seen['reference']==tmp_path/'reference' and seen['validation_source']==tmp_path/'source'
    assert seen['payload_code'] and seen['payload_arguments'][1]=='1'

def test_analysis_command_has_no_reference_mount_and_validation_has_readonly_source(tmp_path):
    from unpacker.sandbox_cli import build_command
    sample=tmp_path/'source';sample.write_bytes(b'benign');ref=tmp_path/'original';ref.write_bytes(b'known')
    analysis=build_command(sample,tmp_path,[])
    assert '/reference.bin' not in analysis and '/source.bin' not in analysis
    validator=build_command(sample,tmp_path,[],reference=ref,payload_code='pass',payload_arguments=[],validation_source=sample)
    assert '/reference.bin' in validator and '/source.bin' in validator
