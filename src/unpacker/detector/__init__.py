"""
Packer detector: multi-method detection pipeline. Supports PE and ELF.
"""
from unpacker.detector.pipeline import DetectorPipeline
from unpacker.detector.base import DetectorMethod
from unpacker.detector.format_ import get_format, load_binary
from unpacker.detector.signatures import SignatureDetector
from unpacker.detector.sections import SectionDetector
from unpacker.detector.entropy import EntropyDetector
from unpacker.detector.heuristics import HeuristicsDetector

__all__ = [
    "DetectorMethod",
    "DetectorPipeline",
    "get_format",
    "load_binary",
    "SignatureDetector",
    "SectionDetector",
    "EntropyDetector",
    "HeuristicsDetector",
]
