import hashlib,stat,sys
from pathlib import Path
import pytest
from unpacker import runtime_gate as gate

@pytest.mark.parametrize('version',['0.9.0','0.11.2','0.12.0-extra','999.invalid'])
def test_reject_old_or_ambiguous_version(tmp_path,monkeypatch,version):
    tool=tmp_path/'bwrap';tool.write_bytes(b'trusted fixture, not executed');tool.chmod(0o700)
    monkeypatch.setattr(gate,'run_command',lambda *a,**k:dict(returncode=0,timed_out=False,stdout='bubblewrap '+version))
    with pytest.raises(ValueError):gate.require_runtime(tool)

def test_patched_path_and_digest(tmp_path,monkeypatch):
    tool=tmp_path/'bwrap';tool.write_bytes(b'benign metadata');tool.chmod(0o700);calls=[]
    def run(cmd,**kwargs):
        calls.append((cmd,kwargs));return dict(returncode=0,timed_out=False,stdout='bubblewrap 0.12.0\n')
    monkeypatch.setattr(gate,'run_command',run)
    result=gate.require_runtime(tool)
    assert result['path']==str(tool) and result['sha256']==hashlib.sha256(tool.read_bytes()).hexdigest()
    assert calls==[([str(tool),'--version'],dict(timeout=2,max_output_mb=1))]

@pytest.mark.parametrize('mode',[0o4777,0o2770,0o702])
def test_reject_privileged_or_untrusted_binary(tmp_path,monkeypatch,mode):
    tool=tmp_path/'bwrap';tool.write_bytes(b'not executed');tool.chmod(mode)
    monkeypatch.setattr(gate,'run_command',lambda *a,**k:pytest.fail('Unsafe tool executed'))
    with pytest.raises(ValueError):gate.require_runtime(tool)

def test_runtime_rejection_before_input_or_output(tmp_path,monkeypatch,capsys):
    import unpacker.sandbox_cli as cli
    out=tmp_path/'output'
    def reject(*args):raise ValueError('patched runtime required')
    monkeypatch.setattr(gate,'require_runtime',reject)
    monkeypatch.setattr(cli,'snapshot_input' if hasattr(cli,'snapshot_input') else 'run_command',lambda *a,**k:pytest.fail('Worker started'))
    monkeypatch.setattr(sys,'argv',['sandbox',str(tmp_path/'absent'),'-o',str(out)])
    assert cli.main()==2 and not out.exists()
    assert 'patched runtime required' in capsys.readouterr().err
