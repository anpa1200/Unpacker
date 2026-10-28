"""
Unpacker modules registry and dispatcher.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import math
import tempfile
import time

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers.upx import UPXUnpacker
from unpacker.unpackers.aspack import ASPackUnpacker
from unpacker.unpackers.mpress import MPRESSUnpacker
from unpacker.unpackers.themida import ThemidaUnpacker
from unpacker.unpackers.vmprotect import VMProtectUnpacker
from unpacker.unpackers.generic import GenericUnpacker
from unpacker.unpackers.enigma import EnigmaUnpacker
from unpacker.unpackers.elf_note import ELFNoteUnpacker
from unpacker.unpackers.ezuri import EzuriUnpacker
from unpacker.unpackers.pakkero import PakkeroUnpacker


# Default set of unpackers; can be extended by registering more
_REGISTRY: list[BaseUnpacker] = [
    UPXUnpacker(),
    ASPackUnpacker(),
    MPRESSUnpacker(),
    ThemidaUnpacker(),
    VMProtectUnpacker(),
    EnigmaUnpacker(),
    ELFNoteUnpacker(),
    EzuriUnpacker(),
    PakkeroUnpacker(),
    GenericUnpacker(),
]


def register_unpacker(unpacker: BaseUnpacker) -> None:
    _REGISTRY.append(unpacker)


def get_unpacker_for(packer_id: str, sample_path: Path) -> BaseUnpacker | None:
    """Return the first unpacker that can_handle(packer_id, sample_path)."""
    for u in _REGISTRY:
        if u.can_handle(packer_id, sample_path):
            return u
    return None


def unpack_with_dispatcher(
    sample_path: Path,
    packer_id: str,
    options: UnpackOptions,
) -> UnpackResult:
    """Select unpacker by packer_id and run unpack."""
    attempt_started=time.monotonic()
    sample_path = Path(sample_path)
    if not math.isfinite(options.timeout_seconds) or options.timeout_seconds <= 0:
        return UnpackResult(False, error="Invalid timeout", status="input_error")
    if (not 1 <= options.max_output_size_mb <= 512 or not 1 <= options.max_input_size_mb <= 512
        or type(options.max_total_output_size_mb) is not int or not 1<=options.max_total_output_size_mb<=4096
        or type(options.max_output_entries) is not int or not 1<=options.max_output_entries<=100000):
        return UnpackResult(False, error="Invalid size limit", status="input_error")
    if not sample_path.is_file() or sample_path.stat().st_size > options.max_input_size_mb * 1024 * 1024:
        return UnpackResult(False, error="Missing, nonregular or oversized input", status="input_error")
    options.output_dir.mkdir(parents=True, exist_ok=True)
    from unpacker.budget import check_output_budget
    budget_root=options.output_dir.resolve()
    budget_error=check_output_budget(budget_root,options.max_total_output_size_mb*1024*1024,options.max_output_entries)
    if budget_error:return UnpackResult(False,error=budget_error,status="resource_limit")
    options = replace(options,extra={**options.extra,"output_budget_root":str(budget_root)}, output_dir=Path(tempfile.mkdtemp(prefix="attempt-", dir=options.output_dir)).resolve())
    sample_path = sample_path.resolve()
    unpacker = get_unpacker_for(packer_id, sample_path)
    if unpacker is None:
        unpacker = get_unpacker_for("generic", sample_path)
    if unpacker is None:
        return UnpackResult(
            success=False,
            error=f"No unpacker available for packer_id={packer_id}",
        )
    try:
        result = unpacker.unpack(sample_path, options)
        budget_error=check_output_budget(budget_root,options.max_total_output_size_mb*1024*1024,options.max_output_entries)
        if budget_error:return UnpackResult(False,error=budget_error,status="resource_limit")
        if result.output_buffer is not None and result.output_path is None:
            if not 0 < len(result.output_buffer) <= options.max_output_size_mb * 1024 * 1024:
                return UnpackResult(False, error="Empty or oversized output buffer")
            path = options.output_dir / "buffer.bin"
            with path.open("xb") as f: f.write(result.output_buffer)
            result.output_path = path
            result.output_buffer = None
        budget_error=check_output_budget(budget_root,options.max_total_output_size_mb*1024*1024,options.max_output_entries)
        if budget_error:return UnpackResult(False,error=budget_error,status="resource_limit")
        if result.output_path:
            options=replace(options,timeout_seconds=max(.001,options.timeout_seconds-(time.monotonic()-attempt_started)))
            from unpacker.validation import validate_artifact
            state, facts = validate_artifact(sample_path, result.output_path, options, result.artifact_kind or "reconstructed_pe")
            result.validation_status = state
            result.metadata.update(facts)
            if facts.get("static_analysis_failure"):
                result.status="timeout" if facts.get("validation_timed_out") else "backend_error"
            if state in {"invalid", "partial"}:
                result.success = False
                if result.status not in {"timeout", "backend_error", "resource_limit"}:
                    result.status = "partial" if state == "partial" else "failed"
                result.error = result.error or facts.get("reason", "Artifact validation failed")
                if state == "invalid": result.output_path = None
        elif result.success and not result.output_buffer:
            result.success = False
            result.error = "Backend returned success without an owned artifact"
        if result.success: result.status = "completed"
        return result
    except Exception as exc:
        return UnpackResult(False, error=f"Backend error: {type(exc).__name__}", status="backend_error")


__all__ = [
    "BaseUnpacker",
    "UPXUnpacker",
    "ASPackUnpacker",
    "MPRESSUnpacker",
    "ThemidaUnpacker",
    "VMProtectUnpacker",
    "GenericUnpacker",
    "EnigmaUnpacker",
    "register_unpacker",
    "get_unpacker_for",
    "unpack_with_dispatcher",
]
