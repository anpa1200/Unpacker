"""Traceable, bounded layer orchestration with explicit terminal outcomes."""
from __future__ import annotations
from dataclasses import dataclass, field
import math
import time
from pathlib import Path
from unpacker.deadlines import DeadlinePlan
from unpacker.types import DEFAULT_DECODE_TIMEOUT_SECONDS, DetectionResult, UnpackOptions, UnpackResult
from unpacker.detector import DetectorPipeline
from unpacker.unpackers import unpack_with_dispatcher
from unpacker.validation import sha256


@dataclass
class LayerResult:
    packer_id: str
    unpack_result: UnpackResult
    output_path: Path | None = None
    detection: DetectionResult | None = None
    input_sha256: str | None = None
    output_sha256: str | None = None


@dataclass
class UnpackerReport:
    sample_path: Path
    detection: DetectionResult | None = None
    layers: list[LayerResult] = field(default_factory=list)
    final_path: Path | None = None
    error: str | None = None
    status: str = "not_started"
    stop_reason: str | None = None
    final_detection: DetectionResult | None = None


def run(sample_path,output_dir,max_layers=5,confidence_threshold=.5,timeout_seconds=DEFAULT_DECODE_TIMEOUT_SECONDS,
        rebuild_iat=False,allow_emulation=False,max_output_size_mb=32,max_input_size_mb=32,
        total_timeout_seconds=300.,packer_id=None,reference=None,rootfs=None,
        max_total_output_size_mb=128,max_output_entries=4096,guest_yesno_answer="no",guest_module_profile="named-exports"):
    sample_path,output_dir=Path(sample_path),Path(output_dir)
    report=UnpackerReport(sample_path)
    try:
        deadlines=DeadlinePlan(timeout_seconds,total_timeout_seconds)
        timeout_seconds,total_timeout_seconds=deadlines.decode_seconds,deadlines.job_seconds
    except ValueError:
        report.error="Invalid layer/time budget";report.status="input_error";return report
    if type(max_layers) is not int or not 1<=max_layers<=32:
        report.error="Invalid layer/time budget";report.status="input_error";return report
    if type(guest_yesno_answer) is not str or guest_yesno_answer not in {"yes","no"}:
        report.error="Invalid guest YES/NO policy";report.status="input_error";return report
    if type(guest_module_profile) is not str or guest_module_profile not in {'named-exports','core-strict'}:
        report.error="Invalid guest module profile";report.status="input_error";return report
    if rebuild_iat:
        report.error="Standalone IAT rebuild is not implemented; no silent no-op";report.status="unsupported";return report
    if not sample_path.is_file() or sample_path.stat().st_size>max_input_size_mb*1024*1024:
        report.error="Invalid or oversized input";report.status="input_error";return report
    if (type(max_total_output_size_mb) is not int or not 1<=max_total_output_size_mb<=4096 or
        type(max_output_entries) is not int or not 1<=max_output_entries<=100000):
        report.error="Invalid aggregate output budget";report.status="input_error";return report
    pipeline=DetectorPipeline(confidence_threshold=confidence_threshold,max_input_size_mb=max_input_size_mb)
    current=sample_path
    seen={sha256(current)}
    deadline=time.monotonic()+total_timeout_seconds
    for index in range(max_layers):
        if time.monotonic()>=deadline:
            report.error="Total job deadline exceeded";report.status="timeout";report.stop_reason="budget_exceeded";break
        pipeline.static_timeout_seconds=min(10,max(.001,deadline-time.monotonic()))
        detected=pipeline.detect(current)
        if index==0:report.detection=detected
        report.final_detection=detected
        if detected.status in {"input_error","parse_error","unsupported_format","inconclusive"} and not (packer_id and index==0):
            report.error="Detection could not establish a supported analysis: "+detected.status
            report.status=detected.status;report.stop_reason=detected.status;break
        chosen=packer_id if index==0 and packer_id else detected.best_packer_id
        if chosen is None or (not detected.is_packed and not (packer_id and index==0)):
            report.status="extracted" if report.layers else "no_packing_evidence"
            report.stop_reason="no_further_packing_evidence"
            break
        if index>0 and chosen=="unknown":
            report.status="extracted_with_residual_evidence"
            report.stop_reason="residual_heuristics";break
        opts=UnpackOptions(output_dir,timeout_seconds=min(timeout_seconds,max(.001,deadline-time.monotonic())),
            rebuild_iat=False,max_output_size_mb=max_output_size_mb,allow_emulation=allow_emulation,
            max_input_size_mb=max_input_size_mb,max_total_output_size_mb=max_total_output_size_mb,
            max_output_entries=max_output_entries,extra={"guest_yesno_answer":guest_yesno_answer,"guest_module_profile":guest_module_profile,**({"reference":str(reference)} if reference else {}),**({"rootfs":str(rootfs)} if rootfs else {})})
        before=sha256(current)
        result=unpack_with_dispatcher(current,chosen,opts)
        output=result.output_path
        after=sha256(output) if output and output.is_file() and not output.is_symlink() else None
        report.layers.append(LayerResult(chosen,result,output,detected,before,after))
        if output:report.final_path=output
        if not result.success:
            report.error=result.error or "Extraction failed"
            report.status=result.status if result.status!="completed" else "failed"
            report.stop_reason=report.status;break
        if not after:
            report.error="No owned output";report.status="failed";report.stop_reason="missing_output";break
        if after in seen:
            report.error="No progress or repeated artifact";report.status="partial";report.stop_reason="no_change_or_cycle";break
        seen.add(after)
        current=output
        if result.validation_status == "vendor_validated":
            report.status="extracted_vendor_format"
            report.stop_reason="native_format_not_parser_validated";break
        if result.artifact_kind in {"reconstructed_pe","memory_snapshot","partial_dump"}:
            report.status="extracted" if result.validation_status=="known_answer_verified" else "extracted_unverified"
            report.stop_reason="emulation_artifact_requires_review";break
    else:
        pipeline.static_timeout_seconds=min(10,max(.001,deadline-time.monotonic()))
        report.final_detection=pipeline.detect(current)
        if report.final_detection.status in {"input_error","parse_error","unsupported_format","inconclusive"}:
            report.status="partial";report.stop_reason="final_detection_inconclusive"
            report.error="Final artifact detection failed: "+report.final_detection.status
        elif report.final_detection.is_packed:
            report.status="partial";report.stop_reason="depth_limit";report.error="Layer limit reached with remaining packing evidence"
        else:
            report.status="extracted";report.stop_reason="no_further_packing_evidence"
    return report
