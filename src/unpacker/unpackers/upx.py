"""Native UPX extraction with bounded resources and exact output ownership."""
import shutil
from pathlib import Path
from unpacker.process import run_command
from unpacker.types import UnpackResult
from unpacker.unpackers.base import BaseUnpacker

class UPXUnpacker(BaseUnpacker):
    @property
    def packer_id(self): return "upx"

    def unpack(self, sample_path, options):
        options.output_dir.mkdir(parents=True, exist_ok=True)
        out = options.output_dir / "decompressed.bin"
        if out.exists() or out.is_symlink():
            return UnpackResult(False, error="Output collision")
        tool = shutil.which("upx")
        if tool is None:
            return UnpackResult(False, error="UPX not installed", status="dependency_error")
        result = run_command([tool, "-d", "-o", str(out.resolve()), str(sample_path.resolve())],
                             timeout=options.timeout_seconds, max_output_mb=options.max_output_size_mb,
                             cwd=options.output_dir,output_root=options.extra.get("output_budget_root",options.output_dir),
                             max_total_output_mb=options.max_total_output_size_mb,max_output_entries=options.max_output_entries)
        logs = [result["stdout"], result["stderr"]]
        if result.get("output_limit_exceeded"):
            return UnpackResult(False,log=logs,error=result["output_limit_exceeded"],status="resource_limit")
        if result["timed_out"]:
            return UnpackResult(False, output_path=out if out.is_file() else None, log=logs, error="UPX timeout", status="timeout")
        if result["returncode"] != 0 or not out.is_file():
            return UnpackResult(False, log=logs, error=f"UPX decompression failed (exit {result['returncode']})")
        return UnpackResult(True, output_path=out, log=logs, status="completed",
                            artifact_kind="native_decompressed_file", metadata={"method":"upx_native","tool":tool})
