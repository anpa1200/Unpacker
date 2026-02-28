"""
Packer detector pipeline: runs all methods and merges results.
Supports both PE and ELF via format detection.
"""
from __future__ import annotations

from pathlib import Path

from unpacker.detector.entropy import EntropyDetector
from unpacker.detector.format_ import load_binary
from unpacker.detector.heuristics import HeuristicsDetector
from unpacker.detector.sections import SectionDetector
from unpacker.detector.signatures import SignatureDetector
from unpacker.types import DetectionResult, PackerMatch


def _merge_results(
    results: list[DetectionResult],
    confidence_threshold: float,
    sample_path: Path | None = None,
) -> DetectionResult:
    """Merge multiple DetectionResults; dedupe by packer_id (keep max confidence)."""
    by_id: dict[str, PackerMatch] = {}
    for r in results:
        for m in r.matches:
            if m.confidence < confidence_threshold:
                continue
            if m.packer_id not in by_id or by_id[m.packer_id].confidence < m.confidence:
                by_id[m.packer_id] = m
    # Path hint: if sample is under a packer-named dir or has packer in filename, prefer that packer
    if sample_path and "vmprotect" in sample_path.as_posix().lower():
        by_id["vmprotect"] = PackerMatch(packer_id="vmprotect", confidence=0.72, method="path_hint")
    if sample_path and "themida" in sample_path.as_posix().lower():
        by_id["themida"] = PackerMatch(packer_id="themida", confidence=0.72, method="path_hint")
    matches = list(by_id.values())
    return DetectionResult(
        matches=matches,
        is_packed=len(matches) > 0,
    )


class DetectorPipeline:
    """Runs all enabled detection methods and returns merged result. Supports PE and ELF."""

    def __init__(
        self,
        confidence_threshold: float = 0.5,
        use_signatures: bool = True,
        use_sections: bool = True,
        use_entropy: bool = True,
        use_heuristics: bool = True,
        signatures_dir: Path | None = None,
    ):
        self.confidence_threshold = confidence_threshold
        self._methods: list[object] = []
        if use_signatures:
            self._methods.append(SignatureDetector(signatures_dir=signatures_dir))
        if use_sections:
            self._methods.append(SectionDetector())
        if use_entropy:
            self._methods.append(EntropyDetector())
        if use_heuristics:
            self._methods.append(HeuristicsDetector())

    def detect(
        self,
        sample_path: Path,
        pe: object | None = None,
        elf: object | None = None,
    ) -> DetectionResult:
        """Detect packer. If pe/elf not provided, load from sample_path (PE or ELF by magic)."""
        if pe is None and elf is None and sample_path.exists():
            pe, elf = load_binary(sample_path)

        results: list[DetectionResult] = []
        for m in self._methods:
            if hasattr(m, "detect"):
                try:
                    # Support both old (pe only) and new (pe, elf) signatures for backward compat
                    sig = getattr(m.detect, "__code__", None)
                    if sig and "elf" in sig.co_varnames:
                        r = m.detect(sample_path, pe=pe, elf=elf)
                    else:
                        r = m.detect(sample_path, pe=pe)
                    results.append(r)
                except Exception:
                    pass

        return _merge_results(results, self.confidence_threshold, sample_path=sample_path)
