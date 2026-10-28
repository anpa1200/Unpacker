"""
Signature-based packer detection (PEiD-style pattern matching).
"""
from __future__ import annotations

from pathlib import Path
import json
import re

from unpacker.types import DetectionResult, PackerMatch


def _load_signatures(signatures_dir: Path) -> list[tuple[str, bytes, int]]:
    """Bounded JSON rule loader. offset=-1 means the mapped PE entry point."""
    rules = []
    for path in sorted(signatures_dir.glob("*.json"))[:32]:
        if path.is_symlink() or path.stat().st_size > 131072:
            raise ValueError("Signature database file exceeds limits")
        data = json.loads(path.read_text())
        if not isinstance(data,list) or len(data)>256:
            raise ValueError("Signature database must be a bounded list")
        for rule in data:
            name,pattern,offset=rule["packer_id"],rule["pattern"],rule["offset"]
            if not isinstance(name,str) or not re.fullmatch(r"[a-z0-9_-]{1,64}",name):
                raise ValueError("Invalid signature packer ID")
            if type(offset) is not int or not -1<=offset<=32*1024*1024:
                raise ValueError("Invalid signature offset")
            if not isinstance(pattern,str) or not 2<=len(pattern)<=512:
                raise ValueError("Invalid signature pattern")
            raw=bytes.fromhex(pattern)
            if not raw or len(raw)>128:raise ValueError("Invalid signature pattern size")
            rules.append((name,raw,offset))
            if len(rules)>2048:raise ValueError("Too many signatures")
    return rules


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
            if self.signatures_dir is not None:
                base = self.signatures_dir
            else:
                # Prefer repo-style layout (src/unpacker/detector -> ../../data/signatures)
                base = Path(__file__).resolve().parent / "rules"
            self._signatures = _load_signatures(base)
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
            if offset == -1 and pe is not None:
                offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
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
