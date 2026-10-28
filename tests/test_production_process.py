"""Benign owned-process trees validate cancellation and descendant cleanup."""
import os
import signal
import subprocess
import sys
import time
import pytest

from unpacker.process import run_command


def job(tmp_path, parent_exits=False):
    ready, late = tmp_path/'ready', tmp_path/'late'
    child = f"from pathlib import Path;import time;Path({str(ready)!r}).touch();time.sleep(.35);Path({str(late)!r}).write_text('late')"
    parent = ("import subprocess,sys,time;from pathlib import Path;"
              f"subprocess.Popen([sys.executable,'-I','-B','-c',{child!r}]);"
              f"ready=Path({str(ready)!r});deadline=time.monotonic()+2\n"
              "while not ready.exists() and time.monotonic()<deadline:time.sleep(.005)\n"
              + ("" if parent_exits else "time.sleep(5)\n"))
    return [sys.executable, '-I', '-B', '-c', parent], ready, late


@pytest.mark.skipif(os.name!='posix', reason='Owned POSIX process group regression')
@pytest.mark.parametrize('decode_budget',[3,180])
def test_cancelled_supervisor_kills_owned_tree_before_propagating(tmp_path, monkeypatch,decode_budget):
    import unpacker.budget as budget
    import unpacker.process as process
    command, ready, late = job(tmp_path)
    owned=[]
    original=process.subprocess.Popen
    def capture(*args,**kwargs):
        child=original(*args,**kwargs);owned.append(child);return child
    def cancelled(*_):
        if ready.exists():raise KeyboardInterrupt('synthetic analyst cancellation')
    monkeypatch.setattr(process.subprocess,'Popen',capture)
    monkeypatch.setattr(budget,'check_output_budget',cancelled)
    try:
        with pytest.raises(KeyboardInterrupt):
            run_command(command,decode_budget,output_root=tmp_path)
        time.sleep(.45)
        assert not late.exists(), 'Descendant continued writing after cancellation'
        assert owned[0].poll() is not None, 'Supervisor did not reap the direct child'
    finally:
        # Also contain the expected pre-fix failure of this regression.
        for child in owned:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=3)


@pytest.mark.skipif(os.name!='posix', reason='Owned POSIX process group regression')
@pytest.mark.parametrize('parent_exits',[False,True])
def test_timeout_and_normal_exit_stop_descendant_writes(tmp_path,parent_exits,monkeypatch):
    import unpacker.process as process
    command,ready,late=job(tmp_path,parent_exits)
    if not parent_exits:
        # Trigger the actual deadline branch after the child's handshake,
        # instead of assuming two Python processes start within 200 ms.
        clock=time.monotonic
        monkeypatch.setattr(process.time,'monotonic',lambda:clock()+(10 if ready.exists() else 0))
    result=run_command(command,3,output_root=tmp_path)
    assert ready.exists()
    assert result['timed_out'] is (not parent_exits)
    time.sleep(.45)
    assert not late.exists()


def test_sandbox_uses_base_stdlib_when_installed_in_virtualenv(tmp_path,monkeypatch):
    import unpacker.sandbox_cli as sandbox
    monkeypatch.setattr(sandbox.shutil,'which',lambda _:'/usr/bin/bwrap')
    monkeypatch.setattr(sandbox.sys,'prefix','/fixture/venv')
    base=tmp_path/'base-python'
    version='python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)
    packages=base/'lib'/version/'site-packages'
    packages.mkdir(parents=True)
    monkeypatch.setattr(sandbox.sys,'base_prefix',str(base))
    monkeypatch.setattr(sandbox.site,'getsitepackages',lambda prefixes:[str(packages)])
    command=sandbox.build_command(tmp_path/'input',tmp_path,[])
    assert [str(base/'lib'),'/runtime/lib'] in [command[i:i+2] for i in range(len(command)-1)]
    assert '/fixture/venv/lib' not in command
    projected='/runtime/lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'/site-packages'
    assert ['--tmpfs',projected] in [command[i:i+2] for i in range(len(command)-1)]
    assert ['--remount-ro',projected] in [command[i:i+2] for i in range(len(command)-1)]
