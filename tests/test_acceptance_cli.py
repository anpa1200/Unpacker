"""Automation must explicitly distinguish completion from accepted recovery."""
import sys
import pytest
from pathlib import Path
from unpacker.orchestrator import UnpackerReport

@pytest.mark.parametrize('status',['no_packing_evidence','extracted_unverified','extracted_with_residual_evidence'])
def test_require_accepted_does_not_return_zero_for_completion_only(monkeypatch,status):
    import unpacker.cli as cli
    monkeypatch.setattr(cli,'run',lambda *a,**k:UnpackerReport(Path('benign'),status=status))
    monkeypatch.setattr(sys,'argv',['unpacker','benign','--require-accepted','--json'])
    assert cli.main()==1

def test_legacy_completion_exit_is_not_silently_redefined(monkeypatch):
    import unpacker.cli as cli
    monkeypatch.setattr(cli,'run',lambda *a,**k:UnpackerReport(Path('benign'),status='no_packing_evidence'))
    monkeypatch.setattr(sys,'argv',['unpacker','benign','--json'])
    assert cli.main()==0
