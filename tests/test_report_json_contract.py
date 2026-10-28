"""Finite, unambiguous controller evidence; benign bytes and mocked transport."""
import hashlib
import math
import time

import pytest

from unpacker.report_integrity import check_report, load_report, verify_artifacts


@pytest.mark.parametrize('number', ['1e999', '-1e999', '1.0e9999'])
def test_overflowing_report_number_is_rejected(tmp_path, number):
    path = tmp_path / 'report.json'
    path.write_text('{"sample_path":"/input.bin","status":"no_packing_evidence",'
                    '"layers":[],"final_path":null,"extra":{"elapsed":' + number + '}}')
    with pytest.raises(ValueError):
        load_report(path)


@pytest.mark.parametrize('number', ['1e308', '-1e308', '1e-200', '0.0'])
def test_finite_report_numbers_remain_supported(tmp_path, number):
    path = tmp_path / 'report.json'
    path.write_text('{"elapsed":' + number + '}')
    assert math.isfinite(load_report(path)['elapsed'])


@pytest.mark.parametrize('depth,accepted', [(64, True), (65, False)])
def test_report_container_depth_budget(tmp_path, depth, accepted):
    path = tmp_path / 'report.json'
    path.write_text('[' * depth + '0' + ']' * depth)
    if accepted:
        value = load_report(path)
        for _ in range(depth): value = value[0]
        assert value == 0
    else:
        with pytest.raises(ValueError): load_report(path)


def report_fixture(tmp_path):
    original = tmp_path / 'source.bin'
    original.write_bytes(b'benign original')
    artifact = tmp_path / 'artifacts/attempt/output.bin'
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b'benign transport candidate')
    before = hashlib.sha256(original.read_bytes()).hexdigest()
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    path = '/out/artifacts/attempt/output.bin'
    result = {'success': True, 'output_path': path, 'metadata': {},
              'validation_status': 'not_checked', 'warnings': [],
              'artifact_kind': 'decompressed_file'}
    report = {'sample_path': '/input.bin', 'status': 'extracted', 'final_path': path,
              'layers': [{'input_sha256': before, 'output_sha256': digest,
                          'output_path': path, 'unpack_result': result}]}
    return report, original, digest, check_report(report, tmp_path, before)


@pytest.mark.parametrize('case', ['overflow', 'negative_overflow', 'duplicate_hash', 'nested_duplicate', 'depth'])
def test_independent_response_rejects_ambiguous_or_nonfinite_json(tmp_path, monkeypatch, case):
    import unpacker.process as process
    import unpacker.sandbox_cli as sandbox
    report, original, digest, artifacts = report_fixture(tmp_path)
    if case == 'duplicate_hash':
        raw = '["structurally_valid",{"output_sha256":"wrong","output_sha256":"' + digest + '"}]'
    else:
        extra = {'overflow': '1e999', 'negative_overflow': '-1e999',
                 'nested_duplicate': '{"value":1,"value":2}',
                 'depth': '[' * 1200 + '0' + ']' * 1200}[case]
        raw = '["structurally_valid",{"output_sha256":"' + digest + '","extra":' + extra + '}]'
    monkeypatch.setattr(sandbox, 'build_command', lambda *a, **k: ['inert-validator'])
    monkeypatch.setattr(process, 'run_command', lambda *a, **k: {'returncode': 0, 'timed_out': False, 'stdout': raw})
    with pytest.raises(ValueError):
        verify_artifacts(report, artifacts, original, None, tmp_path, time.monotonic() + 5)


def test_finite_independent_response_preserves_valid_contract(tmp_path, monkeypatch):
    import unpacker.process as process
    import unpacker.sandbox_cli as sandbox
    report, original, digest, artifacts = report_fixture(tmp_path)
    raw = '["structurally_valid",{"output_sha256":"' + digest + '","extra":1e308}]'
    monkeypatch.setattr(sandbox, 'build_command', lambda *a, **k: ['inert-validator'])
    monkeypatch.setattr(process, 'run_command', lambda *a, **k: {'returncode': 0, 'timed_out': False, 'stdout': raw})
    receipt = verify_artifacts(report, artifacts, original, None, tmp_path, time.monotonic() + 5)
    assert receipt['verified_artifacts'][0]['validation_status'] == 'structurally_valid'
    assert math.isfinite(report['layers'][0]['unpack_result']['metadata']['extra'])
