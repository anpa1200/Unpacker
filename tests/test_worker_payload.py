"""Fail-closed parsing of observed kernel cgroup controls, not requests alone."""
from pathlib import Path
import pytest
from unpacker.worker_payload import inspect_boundary

def fixture(tmp_path):
    root=tmp_path/'cgroups';p=root/('unpacker-job-'+'b'*32+'.service');p.mkdir(parents=True)
    values={'memory.max':'2147483648','memory.swap.max':'0','pids.max':'32','cpu.max':'100000 100000'}
    for k,v in values.items():(p/k).write_text(v)
    membership=tmp_path/'membership';membership.write_text('0::/'+p.name+'\n')
    return root,p,membership

def test_observed_limits_are_recorded_with_owned_identity(tmp_path):
    root,p,m=fixture(tmp_path);d=inspect_boundary(root,m)
    assert d['group_wide'] and d['observed_limits']['memory.max']=='2147483648' and not d['persistent_host_changes']

@pytest.mark.parametrize('name,value',[('memory.max','max'),('memory.max','2147483649'),('memory.swap.max','max'),('pids.max','max'),('pids.max','33'),('cpu.max','max 100000'),('cpu.max','200000 100000')])
def test_missing_or_excessive_limits_cannot_fall_back(tmp_path,name,value):
    root,p,m=fixture(tmp_path);(p/name).write_text(value)
    with pytest.raises(ValueError):inspect_boundary(root,m)

def test_unrelated_cgroup_does_not_satisfy_boundary(tmp_path):
    root,p,m=fixture(tmp_path);m.write_text('0::/ordinary-user-session\n')
    with pytest.raises(ValueError):inspect_boundary(root,m)
