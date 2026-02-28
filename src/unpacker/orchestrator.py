"""
Orchestrator: run detector -> select unpacker -> unpack -> optional PE rebuilder; support multi-layer.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass, field

from unpacker.types import DetectionResult, UnpackOptions, UnpackResult
from unpacker.detector import DetectorPipeline
from unpacker.unpackers import unpack_with_dispatcher


@dataclass
class UnpackerReport:
    """Report for one unpacking run (single or multi-layer)."""
    sample_path: Path
    detection: DetectionResult | None = None
    layers: list[LayerResult] = field(default_factory=list)
    final_path: Path | None = None
    error: str | None = None


@dataclass
class LayerResult:
    """Result of one unpacking layer."""
    packer_id: str
    unpack_result: UnpackResult
    output_path: Path | None = None


def run(
    sample_path: Path,
    output_dir: Path,
    max_layers: int = 5,
    confidence_threshold: float = 0.5,
    timeout_seconds: float = 300.0,
    rebuild_iat: bool = True,
) -> UnpackerReport:
    """
    Full pipeline: detect -> unpack (with optional multi-layer) -> optional PE rebuilder.
    """
    report = UnpackerReport(sample_path=sample_path)
    options = UnpackOptions(
        output_dir=output_dir,
        timeout_seconds=timeout_seconds,
        rebuild_iat=rebuild_iat,
    )

    current_path: Path = sample_path
    pipeline = DetectorPipeline(confidence_threshold=confidence_threshold)

    for layer in range(max_layers):
        detection = pipeline.detect(current_path)
        report.detection = detection

        best_id = detection.best_packer_id
        if not detection.is_packed or best_id is None:
            report.final_path = current_path
            break

        result = unpack_with_dispatcher(current_path, best_id, options)
        out_path = result.get_output_path() if result.success else result.output_path
        report.layers.append(
            LayerResult(packer_id=best_id, unpack_result=result, output_path=out_path)
        )

        if not result.success:
            report.error = result.error
            report.final_path = current_path
            break

        if result.output_path and result.output_path.exists():
            current_path = result.output_path
            report.final_path = current_path
        elif result.output_buffer:
            # Write buffer to output_dir and continue
            next_path = output_dir / f"layer_{layer+1}.unpacked.bin"
            next_path.write_bytes(result.output_buffer)
            current_path = next_path
            report.final_path = current_path
        else:
            report.error = "Unpack produced no output path or buffer"
            break

    return report
