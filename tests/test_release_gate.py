"""Reject release test reports that hide skipped optional-dependency coverage."""
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("release_gate", Path(__file__).parents[1]/"scripts/check_release_tests.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@pytest.mark.parametrize("xml", ['<testsuites/>', '<testsuite><testcase><skipped/></testcase></testsuite>',
    '<testsuite><testcase><error/></testcase></testsuite>', '<testsuite><testcase/><error/></testsuite>',
    '<testsuite><testcase><failure/></testcase></testsuite>'])
def test_no_empty_skipped_or_failed_release(xml, tmp_path):
    path = tmp_path/"junit.xml"
    path.write_text(xml)
    with pytest.raises(ValueError): gate.check(path)


def test_passing_release_report(tmp_path):
    path = tmp_path/"junit.xml"
    path.write_text('<testsuites><testsuite><testcase/><testcase/></testsuite></testsuites>')
    assert gate.check(path) == 2


def test_release_rejects_accidentally_narrow_test_selection(tmp_path):
    path=tmp_path/'junit.xml'
    path.write_text('<testsuite><testcase/></testsuite>')
    with pytest.raises(ValueError,match='minimum regression inventory'):gate.check(path,402)
    for value in (0,-1,True):
        with pytest.raises(ValueError):gate.check(path,value)
