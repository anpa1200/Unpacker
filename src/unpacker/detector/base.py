"""
Base interface for packer detection methods.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from unpacker.types import DetectionResult


class DetectorMethod(Protocol):
    """Protocol for a single detection method (signatures, sections, entropy, heuristics)."""

    def detect(
        self,
        sample_path: Path,
        pe: object | None = None,
        elf: object | None = None,
    ) -> DetectionResult:
        """
        Analyze the sample and return detection result.
        pe: optional pre-parsed PE object. elf: optional ELFFile for ELF binaries.
        """
        ...

    @property
    def name(self) -> str:
        """Method name for logging (e.g. 'signatures', 'sections')."""
        ...
