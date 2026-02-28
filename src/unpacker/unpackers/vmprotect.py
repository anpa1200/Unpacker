"""
VMProtect unpacker: Unipacker for PE32 (32-bit), Qiling for PE32+ (64-bit).

- PE32: Unipacker emulates and dumps (unknown packer mode).
- PE32+: Unipacker does not support 64-bit; Qiling is used when available (pip install qiling + rootfs).
"""
from __future__ import annotations

from pathlib import Path

from unpacker.detector.format_ import is_pe32_plus
from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers._unipacker_shared import run_unipacker_emulation, unipacker_available
from unpacker.unpackers._qiling_shared import run_qiling_emulation, qiling_available


class VMProtectUnpacker(BaseUnpacker):
    """VMProtect unpacking: Unipacker (32-bit) or Qiling (64-bit)."""

    @property
    def packer_id(self) -> str:
        return "vmprotect"

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        out_path = options.output_dir / f"{sample_path.stem}.unpacked.vmprotect{sample_path.suffix}"

        if is_pe32_plus(sample_path):
            # 64-bit: use Qiling when available
            if qiling_available():
                return run_qiling_emulation(
                    sample_path,
                    out_path,
                    options,
                    packer_label="qiling_vmprotect",
                )
            return UnpackResult(
                success=False,
                error=(
                    "64-bit VMProtect requires Qiling. Install with: pip install qiling. "
                    "Set QILING_ROOTFS to a Windows x8664 rootfs (see README)."
                ),
            )

        # 32-bit: use Unipacker
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
