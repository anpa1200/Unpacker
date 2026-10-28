"""Explicit CLI/profile selection without executing input code."""
import pytest
from unpacker.cli import build_parser
from unpacker.sandbox_cli import build_parser as sandbox_parser
from unpacker.orchestrator import run


@pytest.mark.parametrize('parser',[build_parser,sandbox_parser])
def test_module_profile_is_explicit_and_core_only_profile_remains_available(parser):
    assert parser().parse_args(['benign.bin']).guest_module_profile=='named-exports'
    assert parser().parse_args(['benign.bin','--guest-module-profile','core-strict']).guest_module_profile=='core-strict'


def test_invalid_profile_fails_before_attempting_to_read_a_sample(tmp_path):
    result=run(tmp_path/'absent',tmp_path/'out',guest_module_profile='untrusted-profile')
    assert result.status=='input_error' and result.error=='Invalid guest module profile'
