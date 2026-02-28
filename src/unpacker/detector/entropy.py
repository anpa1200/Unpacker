"""
Packer detection by section entropy (high entropy => packed/compressed).
Supports both PE and ELF executable regions.
"""
from __future__ import annotations

import math
from pathlib import Path

from unpacker.types import DetectionResult, PackerMatch

# Entropy above this suggests packed/compressed
HIGH_ENTROPY_THRESHOLD = 7.0

# ELF segment flags
PF_X = 1


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _check_entropy_pe(data: bytes, pe: object, threshold: float) -> list[PackerMatch]:
    matches: list[PackerMatch] = []
    for sec in pe.sections:
        if not (sec.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        raw_off = sec.PointerToRawData
        raw_sz = sec.SizeOfRawData
        if raw_sz > 0 and raw_off + raw_sz <= len(data):
            chunk = data[raw_off : raw_off + raw_sz]
            e = _entropy(chunk)
            if e >= threshold:
                matches.append(
                    PackerMatch(
                        packer_id="unknown",
                        confidence=min(0.5 + (e - threshold) * 0.1, 0.85),
                        method="entropy",
                    )
                )
                break
    return matches


def _check_entropy_elf(data: bytes, elf: object, threshold: float) -> list[PackerMatch]:
    matches: list[PackerMatch] = []
    # ELF program headers: PT_LOAD with PF_X (executable)
    try:
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD" and seg["p_type"] != 1:
                continue
            if not (seg["p_flags"] & PF_X):
                continue
            off = seg["p_offset"]
            sz = seg["p_filesz"]
            if sz > 0 and off + sz <= len(data):
                chunk = data[off : off + sz]
                e = _entropy(chunk)
                if e >= threshold:
                    matches.append(
                        PackerMatch(
                            packer_id="unknown",
                            confidence=min(0.5 + (e - threshold) * 0.1, 0.85),
                            method="entropy",
                        )
                    )
                    break
    except Exception:
        pass
    return matches


class EntropyDetector:
    """Detect packing by high entropy in executable sections/segments (PE and ELF)."""

    def __init__(self, threshold: float = HIGH_ENTROPY_THRESHOLD):
        self.threshold = threshold

    @property
    def name(self) -> str:
        return "entropy"

    def detect(
        self,
        sample_path: Path,
        pe: object | None = None,
        elf: object | None = None,
    ) -> DetectionResult:
        if pe is None and elf is None:
            from unpacker.detector.format_ import load_binary
            pe, elf = load_binary(sample_path)
        try:
            data = sample_path.read_bytes()
        except OSError:
            return DetectionResult(is_packed=False)

        matches: list[PackerMatch] = []
        if pe is not None:
            try:
                matches = _check_entropy_pe(data, pe, self.threshold)
            except Exception:
                pass
        elif elf is not None:
            try:
                matches = _check_entropy_elf(data, elf, self.threshold)
            except Exception:
                pass

        return DetectionResult(
            matches=matches,
            is_packed=len(matches) > 0,
        )
