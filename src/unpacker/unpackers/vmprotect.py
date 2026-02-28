"""
VMProtect unpacker: uses Unipacker (emulation-based) when available.

VMProtect is not in Unipacker's known packer list; Unipacker will treat it as unknown
and emulate from the entry point until section hopping or write+execute is detected, then dump.
Requires: pip install unipacker (and setuptools<70 for pkg_resources on Python 3.12+).
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers._unipacker_shared import run_unipacker_emulation, unipacker_available


class VMProtectUnpacker(BaseUnpacker):
    """VMProtect unpacking via Unipacker (emulation; unknown packer mode)."""

    @property
    def packer_id(self) -> str:
        return "vmprotect"

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        out_path = options.output_dir / f"{sample_path.stem}.unpacked.vmprotect{sample_path.suffix}"

        if not unipacker_available():
            return UnpackResult(
                success=False,
                error="Unipacker not available. Install with: pip install unipacker",
            )

        return run_unipacker_emulation(
            sample_path,
            out_path,
            options,
            packer_label="unipacker_vmprotect",
        )
