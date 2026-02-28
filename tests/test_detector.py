"""Tests for packer detector."""
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unpacker.detector import DetectorPipeline, SectionDetector, EntropyDetector
from unpacker.types import DetectionResult


def test_detector_pipeline_returns_result(tmp_path: Path) -> None:
    """Pipeline returns a DetectionResult even on non-PE or missing file."""
    pipeline = DetectorPipeline(confidence_threshold=0.5)
    # Non-existent file: should not crash; may return empty or try to parse
    fake = tmp_path / "nonexistent.exe"
    res = pipeline.detect(fake)
    assert isinstance(res, DetectionResult)
    assert hasattr(res, "matches")
    assert hasattr(res, "is_packed")


def test_section_detector_needs_pe() -> None:
    """SectionDetector with no PE and invalid path returns is_packed=False."""
    det = SectionDetector()
    res = det.detect(Path("/nonexistent"))
    assert res.is_packed is False


def test_is_pe32_plus_missing_file() -> None:
    """is_pe32_plus returns False for missing or non-PE file."""
    from unpacker.detector.format_ import is_pe32_plus
    assert is_pe32_plus(Path("/nonexistent")) is False
