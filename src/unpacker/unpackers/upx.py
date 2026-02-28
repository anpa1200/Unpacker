"""
UPX unpacker: prefer native `upx -d`, fallback to Python or error.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker


class UPXUnpacker(BaseUnpacker):
    @property
    def packer_id(self) -> str:
        return "upx"

    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        log: list[str] = []
        out_path = options.output_dir / f"{sample_path.stem}.unpacked.upx{sample_path.suffix}"

        # Prefer system UPX
        upx_bin = shutil.which("upx")
        if upx_bin:
            try:
                result = subprocess.run(
                    [upx_bin, "-d", "-o", str(out_path), str(sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=options.timeout_seconds,
                )
                log.append(f"upx stdout: {result.stdout}")
                if result.stderr:
                    log.append(f"upx stderr: {result.stderr}")
                if result.returncode == 0 and out_path.exists():
                    return UnpackResult(
                        success=True,
                        output_path=out_path,
                        log=log,
                        metadata={"method": "upx_native"},
                    )
            except subprocess.TimeoutExpired:
                return UnpackResult(success=False, log=log, error="upx timed out")
            except Exception as e:
                log.append(str(e))

        # TODO: Python-based UPX decompression (e.g. pyupx or inline NRV2B/LZMA)
        return UnpackResult(
            success=False,
            log=log,
            error="UPX not found (install 'upx') or unpack failed; Python fallback not implemented",
        )
