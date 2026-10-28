"""Tests for the Unipacker availability diagnostic.

Regression coverage for a real bug report: unipacker_available() swallowed
the actual import error and always reported the generic "not available"
message, even when unipacker was genuinely pip-installed but its own
dependency chain (unicorn -> distutils/pkg_resources) failed to import on
Python 3.12+. See https://github.com/anpa1200/Unpacker/issues/1.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import builtins

from unpacker.unpackers import _unipacker_shared


def test_unipacker_import_error_is_none_when_import_succeeds(monkeypatch):
    fake_unipacker_core = type(sys)("unipacker.core")
    fake_unipacker_core.Sample = object()
    fake_unipacker_core.UnpackerEngine = object()
    fake_unipacker_core.SimpleClient = object()
    monkeypatch.setitem(sys.modules, "unipacker.core", fake_unipacker_core)

    assert _unipacker_shared.unipacker_import_error() is None
    assert _unipacker_shared.unipacker_available() is True


def test_unipacker_import_error_surfaces_the_real_exception(monkeypatch):
    """Reproduces the reported failure: unipacker is installed, but importing
    unipacker.core fails deep in its own dependency chain. The real exception
    text must be returned, not swallowed into a generic bool."""
    monkeypatch.delitem(sys.modules, "unipacker.core", raising=False)

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "unipacker.core" or name.startswith("unipacker.core"):
            raise ModuleNotFoundError("No module named 'distutils'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    error = _unipacker_shared.unipacker_import_error()

    assert error is not None
    assert "distutils" in error
    assert _unipacker_shared.unipacker_available() is False


def test_install_hint_points_at_the_reviewed_runtime():
    # Missing/broken engines must point to the reviewed offline runtime.
    assert "release bundle" in _unipacker_shared.UNIPACKER_INSTALL_HINT
    assert "hashed lock" in _unipacker_shared.UNIPACKER_INSTALL_HINT
    assert "setuptools<81" not in _unipacker_shared.UNIPACKER_INSTALL_HINT
