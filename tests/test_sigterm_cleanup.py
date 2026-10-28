"""Signals target only short-lived benign supervisors created by these tests."""
import json,os,signal,subprocess,sys,time
from pathlib import Path
import pytest
from unpacker.process import run_command,_sigterm_cancellation

def wait_file(path,child):
    deadline=time.monotonic()+8
    while not path.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.01)
    assert path.exists(),'Owned benign worker did not start'

@pytest.mark.skipif(os.name!='posix',reason='POSIX owned supervisor signal contract')
@pytest.mark.parametrize('term_during_spawn',[False,True])
def test_sigterm_cleans_owned_tree_including_spawn_window(tmp_path,term_during_spawn):
    ready,late=tmp_path/'ready',tmp_path/'late'
    grandchild=f"from pathlib import Path;import time;Path({str(ready)!r}).touch();time.sleep(.6);Path({str(late)!r}).write_text('leak')"
    worker="import subprocess,sys,time;subprocess.Popen([sys.executable,'-I','-B','-c',"+repr(grandchild)+"]);time.sleep(10)"
    source=str(Path(__file__).resolve().parents[1]/'src')
    # Installed verification substitutes the actual package location; the copied
    # suite has no src tree and cannot accidentally import a checkout.
    import unpacker
    source=str(Path(unpacker.__file__).resolve().parent.parent)
    supervisor=f"""import sys,os,signal
sys.path.insert(0,{source!r})
import unpacker.process as m
if {term_during_spawn!r}:
    original=m.subprocess.Popen
    def spawn(*args,**kwargs):
        child=original(*args,**kwargs)
        os.kill(os.getpid(),signal.SIGTERM)
        return child
    m.subprocess.Popen=spawn
try:
    m.run_command([sys.executable,'-I','-B','-c',{worker!r}],180)
except m.ProcessCancelled as exc:
    assert signal.getsignal(signal.SIGTERM)==signal.SIG_DFL
    raise SystemExit(128+exc.signum)
raise SystemExit(99)
"""
    child=subprocess.Popen([sys.executable,'-I','-B','-c',supervisor],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        if not term_during_spawn:
            wait_file(ready,child);os.kill(child.pid,signal.SIGTERM)
        stdout,stderr=child.communicate(timeout=8)
        assert child.returncode==143,(stdout,stderr)
        time.sleep(.75);assert not late.exists(),'Owned descendant wrote after SIGTERM cleanup'
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=3)


def test_default_term_handler_and_child_signal_mask_are_restored():
    before=signal.getsignal(signal.SIGTERM)
    r=run_command([sys.executable,'-I','-B','-c','import signal;print(signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK,set()))'],3)
    assert r['returncode']==0 and r['stdout'].strip()=='False'
    assert signal.getsignal(signal.SIGTERM)==before


def test_existing_application_term_handler_is_not_replaced():
    before=signal.getsignal(signal.SIGTERM)
    def handler(*args):pass
    try:
        signal.signal(signal.SIGTERM,handler)
        with _sigterm_cancellation() as installed:
            assert not installed and signal.getsignal(signal.SIGTERM) is handler
    finally:signal.signal(signal.SIGTERM,before)
