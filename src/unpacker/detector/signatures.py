"""
Signature-based packer detection (PEiD-style pattern matching).
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import DetectionResult, PackerMatch


def _load_signatures(signatures_dir: Path) -> list[tuple[str, bytes, int]]:
    """Load (packer_id, pattern, offset) from data dir. Stub: returns empty."""
    # TODO: load from data/signatures/ (JSON/YAML or PEiD format)
    return []


class SignatureDetector:
    """Detect packers by byte patterns at EP or fixed offsets."""

    def __init__(self, signatures_dir: Path | None = None):
        self.signatures_dir = signatures_dir
        self._signatures: list[tuple[str, bytes, int]] | None = None

    @property
    def name(self) -> str:
        return "signature"

    def _get_signatures(self) -> list[tuple[str, bytes, int]]:
        if self._signatures is None:
            self._signatures = _load_signatures(
                self.signatures_dir or Path(__file__).resolve().parents[2] / ".." / ".." / "data" / "signatures"
            )
        return self._signatures

    def detect(
        self,
        sample_path: Path,
        pe: object | None = None,
        elf: object | None = None,
    ) -> DetectionResult:
        matches: list[PackerMatch] = []
        try:
            data = sample_path.read_bytes()
        except OSError:
            return DetectionResult(is_packed=False)
        for packer_id, pattern, offset in self._get_signatures():
            if offset >= 0 and offset + len(pattern) <= len(data):
                if data[offset : offset + len(pattern)] == pattern:
                    matches.append(PackerMatch(packer_id=packer_id, confidence=0.95, method=self.name))
            elif offset < 0:
                # -1 often means "at EP"; would need pe to get EP RVA and map to file offset
                pass
        return DetectionResult(
            matches=matches,
            is_packed=len(matches) > 0,
        )
