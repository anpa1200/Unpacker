"""Selected base-interpreter package trees are empty RO across Linux layouts."""
from pathlib import Path
import site
import pytest
import unpacker.sandbox_cli as sandbox


def masks(command):
    return {command[i + 1] for i, value in enumerate(command) if value == '--tmpfs'}


def test_base_site_and_dist_packages_are_both_masked(tmp_path, monkeypatch):
    base = tmp_path / 'base'
    version = 'python' + str(sandbox.sys.version_info.major) + '.' + str(sandbox.sys.version_info.minor)
    first = base / 'lib' / version / 'site-packages'
    second = base / 'lib/python3/dist-packages'
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    monkeypatch.setattr(sandbox.sys, 'base_prefix', str(base))
    monkeypatch.setattr(site, 'getsitepackages', lambda prefixes: [str(first), str(second)])
    command = sandbox.build_command(tmp_path / 'sample', tmp_path, [], bubblewrap=Path('/reviewed/bwrap'))
    for path in ['/runtime/lib/' + version + '/site-packages', '/runtime/lib/python3/dist-packages']:
        assert path in masks(command)
        assert ['--remount-ro', path] == command[command.index('--remount-ro', command.index(path)):command.index('--remount-ro', command.index(path)) + 2]


def test_absent_base_site_directory_does_not_require_a_mount_target(tmp_path, monkeypatch):
    base = tmp_path / 'base'
    (base / 'lib').mkdir(parents=True)
    version = 'python' + str(sandbox.sys.version_info.major) + '.' + str(sandbox.sys.version_info.minor)
    missing = base / 'lib' / version / 'site-packages'
    monkeypatch.setattr(sandbox.sys, 'base_prefix', str(base))
    monkeypatch.setattr(site, 'getsitepackages', lambda prefixes: [str(missing)])
    command = sandbox.build_command(tmp_path / 'sample', tmp_path, [], bubblewrap=Path('/reviewed/bwrap'))
    assert '/runtime/lib/' + version + '/site-packages' not in masks(command)


def test_visible_distro_sites_are_masked_at_original_and_projected_paths(tmp_path, monkeypatch):
    sites = ['/usr/lib/python3/dist-packages', '/usr/local/lib/python3.12/dist-packages']
    original = Path.is_dir
    monkeypatch.setattr(Path, 'is_dir', lambda self: str(self) in sites or original(self))
    monkeypatch.setattr(sandbox.sys, 'base_prefix', '/usr')
    monkeypatch.setattr(site, 'getsitepackages', lambda prefixes: sites)
    command = sandbox.build_command(tmp_path / 'sample', tmp_path, [], bubblewrap=Path('/reviewed/bwrap'))
    assert set(sites) | {'/runtime/lib/python3/dist-packages'} <= masks(command)
