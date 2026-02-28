"""
MPRESS unpacker: stub for MPRESS-specific or generic dynamic unpacking.
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker


class MPRESSUnpacker(BaseUnpacker):
    @property
    def packer_id(self) -> str:
        return "mpress"

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        # TODO: MPRESS-specific decompression or generic dynamic
        return UnpackResult(
            success=False,
            log=["MPRESS unpacker not yet implemented; use generic module"],
            error="MPRESS unpacker stub",
        )
