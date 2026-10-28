"""Benign deadline/configuration/cleanup contracts; never wait180 seconds."""
from pathlib import Path
import json,signal,subprocess,sys
import pytest
from unpacker.deadlines import DeadlinePlan,positive_seconds


@pytest.mark.parametrize('value',[0,-1,float('nan'),float('inf'),float('-inf'),True,None,'180'])
def test_invalid_duration_is_rejected(value):
    with pytest.raises(ValueError):positive_seconds(value)


@pytest.mark.parametrize('seconds,job,sandbox,launcher',[(60,90,95,105),(180,210,215,225)])
def test_coordinated_wall_clock_plan_has_bounded_export_and_cleanup(seconds,job,sandbox,launcher):
    p=DeadlinePlan.for_decode(seconds)
    assert (p.job_seconds,p.sandbox_seconds,p.launcher_seconds)==(job,sandbox,launcher)
    assert not p.facts()['shorter_explicit_job_wins']


def test_explicit_short_job_is_not_silently_extended():
    p=DeadlinePlan(180,75)
    assert p.facts()['decode_upper_bound_seconds']==75 and p.facts()['shorter_explicit_job_wins']


@pytest.mark.parametrize('decode,total',[(0,210),(180,0),(float('nan'),210),(180,float('inf'))])
def test_sandbox_rejects_invalid_time_before_creating_outputs(tmp_path,monkeypatch,decode,total):
    import unpacker.sandbox_cli as cli
    sample=tmp_path/'sample';sample.write_bytes(b'benign');out=tmp_path/'out'
    monkeypatch.setattr(sys,'argv',['sandbox',str(sample),'-o',str(out),'--timeout',str(decode),'--total-timeout',str(total)])
    monkeypatch.setattr(cli,'build_command',lambda *a:pytest.fail('Must not launch invalid deadline'))
    assert cli.main()==2 and not out.exists()


def test_sandbox_180_reaches_payload_and_outer_watchdog(tmp_path,monkeypatch):
    import unpacker.sandbox_cli as cli
    import unpacker.evidence_archive as archive
    sample=tmp_path/'sample';sample.write_bytes(b'benign');out=tmp_path/'out';seen={}
    def build(sample,output,arguments,*args,**kwargs):seen['arguments']=arguments;return ['reviewed-benign-tool',*arguments]
    def run(command,**kwargs):
        seen.update(kwargs);kwargs['stdout_file'].write_bytes(b'benign-export-placeholder')
        return dict(returncode=0,timed_out=False,stdout='',stderr='')
    def unpack(path,output,*args):(output/'report.json').write_text('{"status":"no_packing_evidence","sample_path":"/input.bin","layers":[],"final_path":null}');return {'files':1}
    monkeypatch.setattr(__import__('unpacker.runtime_gate',fromlist=['require_runtime']),'require_runtime',lambda *a:{'path':'/mock-bwrap'})
    monkeypatch.setattr(cli,'build_command',build);monkeypatch.setattr(cli,'run_command',run);monkeypatch.setattr(archive,'unpack_evidence',unpack)
    monkeypatch.setattr(sys,'argv',['sandbox',str(sample),'-o',str(out),'--timeout','180','--total-timeout','210','--max-total-output-mb','32'])
    assert cli.main()==0 and seen['timeout']==215
    args=seen['arguments'];assert args[args.index('--timeout')+1]=='180.0' and args[args.index('--total-timeout')+1]=='210.0'
    invocation=json.loads(next(out.glob('run-*/invocation.json')).read_text())
    assert invocation['deadlines']['recommended_outer_launcher_seconds']==225


@pytest.mark.parametrize('override,expected',[([],180),(['--timeout','60'],60)])
def test_extended_yaml_and_explicit_cli_override(tmp_path,monkeypatch,override,expected):
    import unpacker.cli as cli
    from unpacker.configuration import load_config
    from unpacker.orchestrator import UnpackerReport
    config=Path(__file__).resolve().parents[1]/'config/extended-analysis.yaml'
    loaded=load_config(config);assert loaded['timeout_seconds']==180 and loaded['total_timeout_seconds']==210
    assert loaded['max_output_size_mb']==loaded['max_total_output_size_mb']==32 and loaded['max_output_entries']==4096
    seen={}
    def run(sample,out,**kwargs):seen.update(kwargs);return UnpackerReport(Path(sample),status='no_packing_evidence')
    monkeypatch.setattr(cli,'run',run);monkeypatch.setattr(sys,'argv',['unpacker','unused.bin','--config',str(config),*override])
    assert cli.main()==0 and seen['timeout_seconds']==expected and seen['total_timeout_seconds']==210


@pytest.mark.parametrize('value',['0','-1','.nan','.inf'])
def test_yaml_time_rejects_nonpositive_nonfinite_values(tmp_path,value):
    from unpacker.configuration import load_config
    p=tmp_path/'bad.yaml';p.write_text('orchestrator:\n  timeout_seconds: '+value+'\n')
    with pytest.raises(ValueError):load_config(p)


def test_backend_preserves_timeout_and_every_non_time_budget(tmp_path,monkeypatch):
    from unpacker.types import UnpackOptions
    import unpacker.backend_worker as worker
    seen={}
    def run(command,**kwargs):seen.update(kwargs);return dict(returncode=0,timed_out=False,stdout='{"success":false,"status":"unsupported"}',stderr='')
    monkeypatch.setattr(worker,'run_command',run)
    o=UnpackOptions(tmp_path,timeout_seconds=180,max_input_size_mb=7,max_output_size_mb=11,max_total_output_size_mb=13,max_output_entries=17)
    worker.supervise('unipacker',tmp_path/'input',tmp_path/'output',o,'benign')
    assert seen['timeout']==180 and seen['max_total_output_mb']==13 and seen['max_output_entries']==17
    restored=worker._options_from_payload(json.loads(seen['input_text']))
    assert (restored.timeout_seconds,restored.max_input_size_mb,restored.max_output_size_mb,restored.max_total_output_size_mb,restored.max_output_entries)==(180,7,11,13,17)


def test_timeout_never_calls_unbounded_communicate_after_kill(tmp_path,monkeypatch):
    import unpacker.process as process
    calls=[]
    class Child:
        pid=424242;stdin=None;returncode=-9
        def communicate(self,*args,**kwargs):pytest.fail('No unbounded communicate after deadline')
        def wait(self,timeout):calls.append(('wait',timeout));return -9
    clock=iter([0,181])
    monkeypatch.setattr(process.time,'monotonic',lambda:next(clock))
    monkeypatch.setattr(process.subprocess,'Popen',lambda *a,**k:Child())
    monkeypatch.setattr(process.os,'killpg',lambda pid,sig:calls.append(('kill',pid,sig)))
    result=process.run_command([sys.executable,'-c','pass'],180)
    assert result['timed_out'] and ('wait',5) in calls and ('kill',424242,signal.SIGKILL) in calls
