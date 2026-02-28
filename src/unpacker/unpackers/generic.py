"""
Generic unpacker: emulation (Qiling/Speakeasy) or external PE-sieve; handles unknown packers.
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker


class GenericUnpacker(BaseUnpacker):
    """Generic dynamic unpacking via emulation or external tools (PE-sieve, etc.)."""

    @property
    def packer_id(self) -> str:
        return "generic"

    def can_handle(self, packer_id: str, sample_path: Path) -> bool:
        # Generic handles "unknown" or any packer when no specific module exists
        return packer_id.lower() in ("unknown", "generic")

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        # TODO: Option 1 - Qiling/Speakeasy: load PE, hook VirtualAlloc/VirtualProtect etc., run until OEP, dump
        # TODO: Option 2 - Subprocess: run sample under PE-sieve/TinyTracer in VM/sandbox, collect dump
        return UnpackResult(
            success=False,
            log=["Generic unpacker not yet implemented (emulation or PE-sieve integration)"],
            error="Generic unpacker stub",
        )
