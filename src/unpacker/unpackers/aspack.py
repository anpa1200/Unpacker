"""
ASPack unpacker: uses Unipacker (emulation-based) when available.

Requires: pip install '1200km-unpacker[unipacker]' (installs unipacker and a
compatible setuptools for pkg_resources on Python 3.12+).
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers._unipacker_shared import (
    UNIPACKER_INSTALL_HINT,
    run_unipacker_emulation,
    unipacker_import_error,
)


class ASPackUnpacker(BaseUnpacker):
    """ASPack unpacking via Unipacker (emulation)."""

    @property
    def packer_id(self) -> str:
        return "aspack"

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        out_path = options.output_dir / f"{sample_path.stem}.unpacked.aspack{sample_path.suffix}"

        import_error = unipacker_import_error()
        if import_error:
            return UnpackResult(
                success=False,
                error=f"Unipacker could not be loaded ({import_error}). {UNIPACKER_INSTALL_HINT}",
            )

        return run_unipacker_emulation(
            sample_path,
            out_path,
            options,
            packer_label="unipacker",
        )
