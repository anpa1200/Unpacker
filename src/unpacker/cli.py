#!/usr/bin/env python3
"""CLI: unpack a sample (detect -> unpack -> report)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from unpacker.orchestrator import run as orchestrator_run


def main() -> int:
    p = argparse.ArgumentParser(description="Unpacker: packer detection and unpacking")
    p.add_argument("sample", type=Path, help="Path to PE sample")
    p.add_argument("-o", "--output-dir", type=Path, default=Path("unpacked"), help="Output directory")
    p.add_argument("--max-layers", type=int, default=5, help="Max unpacking layers")
    p.add_argument("--confidence", type=float, default=0.5, help="Detection confidence threshold")
    p.add_argument("--timeout", type=float, default=300.0, help="Timeout per unpack (seconds)")
    args = p.parse_args()

    if not args.sample.exists():
        print(f"Error: sample not found: {args.sample}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = orchestrator_run(
        sample_path=args.sample,
        output_dir=args.output_dir,
        max_layers=args.max_layers,
        confidence_threshold=args.confidence,
        timeout_seconds=args.timeout,
    )

    if report.detection:
        best = report.detection.best_match
        if best:
            print(f"Detected: {best.packer_id} (confidence={best.confidence}, method={best.method})")
        elif report.detection.is_packed:
            print("Detected: packed (unknown packer)")
        else:
            print("Detected: not packed")
    for i, layer in enumerate(report.layers):
        status = "ok" if layer.unpack_result.success else "fail"
        print(f"  Layer {i+1}: packer={layer.packer_id} -> {status}")
        if layer.unpack_result.error:
            print(f"    Error: {layer.unpack_result.error}")
    if report.final_path:
        print(f"Final output: {report.final_path}")
    if report.error:
        print(f"Report error: {report.error}", file=sys.stderr)

    return 0 if report.error is None and (not report.layers or report.layers[-1].unpack_result.success) else 1


if __name__ == "__main__":
    raise SystemExit(main())
