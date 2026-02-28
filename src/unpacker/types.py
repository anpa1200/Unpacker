"""
Shared data types for the Unpacker pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class PackerMatch:
    """Single packer detection hit."""
    packer_id: str
    confidence: float  # 0.0 .. 1.0
    method: str  # e.g. "signature", "sections", "entropy", "heuristics"


@dataclass
class DetectionResult:
    """Result of packer detection on a sample."""
    matches: list[PackerMatch] = field(default_factory=list)
    is_packed: bool = False
    raw_pe: Any = None  # optional pefile.PE or similar

    @property
    def best_match(self) -> Optional[PackerMatch]:
        if not self.matches:
            return None
        return max(self.matches, key=lambda m: m.confidence)

    @property
    def best_packer_id(self) -> Optional[str]:
        m = self.best_match
        return m.packer_id if m else None


@dataclass
class UnpackOptions:
    """Options for unpacking a sample."""
    output_dir: Path
    timeout_seconds: float = 300.0
    rebuild_iat: bool = True
    max_output_size_mb: int = 512
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class UnpackResult:
    """Result of an unpack operation."""
    success: bool
    output_path: Optional[Path] = None
    output_buffer: Optional[bytes] = None
    log: list[str] = field(default_factory=list)
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_output_path(self) -> Optional[Path]:
        """Return output_path if set; caller may write output_buffer to disk if only buffer is set."""
        return self.output_path
