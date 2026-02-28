"""
ASPack unpacker: uses Unipacker (emulation-based) when available.

Requires: pip install unipacker and setuptools (for pkg_resources; use setuptools<70 if needed).
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers._unipacker_shared import run_unipacker_emulation, unipacker_available


class ASPackUnpacker(BaseUnpacker):
    """ASPack unpacking via Unipacker (emulation)."""

    @property
    def packer_id(self) -> str:
        return "aspack"

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        out_path = options.output_dir / f"{sample_path.stem}.unpacked.aspack{sample_path.suffix}"

        if not unipacker_available():
            return UnpackResult(
                success=False,
                error="Unipacker not available. Install with: pip install unipacker",
            )

        return run_unipacker_emulation(
            sample_path,
            out_path,
            options,
            packer_label="unipacker",
        )
