"""Tiny benign archives cover implicit-directory amplification before writes."""
import io
import tarfile
import pytest

from unpacker.evidence_archive import unpack_evidence


def make_archive(tmp_path, entries):
    path = tmp_path / 'evidence.tar'
    with tarfile.open(path, 'w') as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return path


@pytest.mark.parametrize('content', [b'', b'benign'])
def test_implicit_directory_entries_fail_before_any_copy(tmp_path, content):
    archive = make_archive(tmp_path, [('a/b/c/output.bin', content)])
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(ValueError): unpack_evidence(archive, out, 4096, max_entries=3)
    assert not list(out.iterdir())


def test_aggregate_implicit_directory_entries_share_one_budget(tmp_path):
    archive = make_archive(tmp_path, [('one/a/output', b'a'), ('two/b/output', b'b')])
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(ValueError): unpack_evidence(archive, out, 8192, max_entries=5)
    assert not list(out.iterdir())


def test_implicit_directories_fit_exact_budget_and_are_reported(tmp_path):
    archive = make_archive(tmp_path, [('a/b/output', b'benign')])
    out = tmp_path / 'out'
    out.mkdir()
    receipt = unpack_evidence(archive, out, 4096, max_entries=3)
    assert receipt['files'] == 1 and receipt['entries'] == 3
    assert receipt['archive_entries'] == 1 and len(list(out.rglob('*'))) == 3
    assert (out / 'a/b/output').read_bytes() == b'benign'


def test_explicit_parent_does_not_double_count_implicit_directory(tmp_path):
    archive = make_archive(tmp_path, [('a', None), ('a/b/output', b'benign')])
    out = tmp_path / 'out'
    out.mkdir()
    receipt = unpack_evidence(archive, out, 4096, max_entries=3)
    assert receipt['entries'] == 3 and receipt['archive_entries'] == 2


def test_normalized_duplicate_paths_are_rejected_before_writing(tmp_path):
    archive = make_archive(tmp_path, [('a//output', b'one'), ('a/output', b'two')])
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(ValueError): unpack_evidence(archive, out, 8192)
    assert not list(out.iterdir())


def test_pax_nul_path_is_rejected_before_any_copy(tmp_path):
    path = tmp_path / 'nul.tar'
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as tar:
        first = tarfile.TarInfo('first')
        first.size = 1
        tar.addfile(first, io.BytesIO(b'x'))
        invalid = tarfile.TarInfo('placeholder')
        invalid.pax_headers = {'path': 'bad\x00name'}
        invalid.size = 1
        tar.addfile(invalid, io.BytesIO(b'x'))
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(ValueError): unpack_evidence(path, out, 8192)
    assert not list(out.iterdir())


@pytest.mark.parametrize('truncated', [False, True])
def test_malformed_transport_uses_the_controller_failure_contract(tmp_path, truncated):
    path = make_archive(tmp_path, [('output', b'x' * 20)])
    path.write_bytes(path.read_bytes()[:517] if truncated else b'not a tar archive')
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(ValueError): unpack_evidence(path, out, 4096)
    assert not list(out.iterdir())
