"""Untrusted worker logs are evidence and cannot inject terminal controls."""
import json,sys
def test_sandbox_does_not_echo_raw_worker_terminal_sequences(tmp_path,monkeypatch,capsys):
    import unpacker.sandbox_cli as cli
    import unpacker.evidence_archive as archive
    sample=tmp_path/'sample';sample.write_bytes(b'benign')
    raw='\x1b]52;c;canary\x07\x1b[2J'
    monkeypatch.setattr(__import__('unpacker.runtime_gate',fromlist=['require_runtime']),'require_runtime',lambda *a:{'path':'/mock-bwrap'})
    monkeypatch.setattr(cli,'build_command',lambda *a,**k:['never-executed'])
    def run(command,**kwargs):
        kwargs['stdout_file'].write_bytes(b'fake-transport')
        return {'returncode':0,'timed_out':False,'stdout':raw,'stderr':raw}
    def unpack(path,output,*args):
        (output/'report.json').write_text(json.dumps({'sample_path':'/input.bin','status':'no_packing_evidence','layers':[],'final_path':None}))
        return {'files':1}
    monkeypatch.setattr(cli,'run_command',run);monkeypatch.setattr(archive,'unpack_evidence',unpack)
    monkeypatch.setattr(sys,'argv',['sandbox',str(sample),'-o',str(tmp_path/'out')])
    assert cli.main()==0
    captured=capsys.readouterr();assert '\x1b' not in captured.out+captured.err and '\x07' not in captured.out+captured.err
    stored=json.loads(next((tmp_path/'out').glob('run-*/process.json')).read_text())
    assert stored['stderr']==raw and stored['completion_status']=='no_packing_evidence'
