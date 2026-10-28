"""Offline registry policy tests; no dependency metadata or network is fetched."""
import importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('dependency_gate',Path(__file__).parents[1]/'scripts/check_dependency_advisories.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)


@pytest.mark.parametrize('rows,expected',[
    ([{'status':'queried','vulnerabilities':[]}],0),
    ([{'status':'queried','vulnerabilities':[{'id':'fixture','withdrawn':'2026-01-01'}]}],0),
    ([{'status':'queried','vulnerabilities':[{'id':'fixture','withdrawn':None}]}],1),
    ([{'status':'unavailable','error_type':'TimeoutError'}],2),
    ([{'status':'queried','vulnerabilities':'untrusted'}],2),
])
def test_advisory_gate_never_treats_unknown_or_active_evidence_as_clear(rows,expected):
    assert gate.verdict(rows)==expected
