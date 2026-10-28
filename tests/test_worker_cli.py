"""Production launcher contracts, without contacting a host service manager."""
import sys
import pytest
from unpacker.worker_cli import build_job
from unpacker.process import run_command

def available(monkeypatch):
    import unpacker.worker_cli as worker
    monkeypatch.setattr(worker.shutil,'which',lambda name:'/usr/bin/'+name)
    monkeypatch.setattr(sys,'platform','linux')

def test_job_boundary_is_finite_group_wide_and_has_empty_controller_environment(monkeypatch):
    available(monkeypatch)
    command,properties,timeout=build_job(['benign','--timeout','180','--total-timeout','210'],'unpacker-job-'+'a'*32)
    assert properties['MemoryMax']==2147483648 and properties['TasksMax']==32 and properties['CPUQuota']=='100%' and properties['MemorySwapMax']==0
    assert properties['KillMode']=='control-group' and properties['TimeoutStopSec']==5 and properties['RuntimeMaxSec']==230
    assert '--collect' in command and '--user' in command and '--pipe' in command
    assert '--require-accepted' in command
    i=command.index('/usr/bin/env');assert command[i+1]=='-i' and 'HOME=/tmp' in command[i:]
    assert timeout==240

@pytest.mark.parametrize('memory,tasks',[(0,32),(2049,32),(2048,0),(2048,33),(True,32)])
def test_job_resource_overrides_cannot_remove_or_raise_existing_limits(monkeypatch,memory,tasks):
    available(monkeypatch)
    with pytest.raises(ValueError):build_job(['benign'],'unpacker-job-'+'a'*32,memory,tasks)

def test_no_service_manager_means_no_weaker_execution_fallback(monkeypatch):
    import unpacker.worker_cli as worker
    monkeypatch.setattr(worker.shutil,'which',lambda name:None)
    with pytest.raises(ValueError):build_job(['benign'],'unpacker-job-'+'a'*32)

@pytest.mark.parametrize('env',[{'API_KEY':'must-not-cross-boundary'},{'HOME':'/private'},{'XDG_RUNTIME_DIR':'bad\x00value'}])
def test_client_environment_extension_never_accepts_credentials_or_unbounded_values(env):
    with pytest.raises(ValueError):run_command([sys.executable,'-c','pass'],1,env_overrides=env)
