"""
Heuristic packer detection (suspicious EP, minimal IAT, etc.).
Supports both PE and ELF.
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import DetectionResult, PackerMatch

PT_LOAD = 1


class HeuristicsDetector:
    """Detect packing by heuristics: EP in last section/segment, tiny IAT, etc."""

    @property
    def name(self) -> str:
        return "heuristics"

    def detect(
        self,
        sample_path: Path,
        pe: object | None = None,
        elf: object | None = None,
    ) -> DetectionResult:
        if pe is None and elf is None:
            from unpacker.detector.format_ import load_binary
            pe, elf = load_binary(sample_path)

        matches: list[PackerMatch] = []
        if pe is not None:
            try:
                ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                num_imports = 0
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        num_imports += len(entry.imports) if hasattr(entry, "imports") else 0
                if pe.sections:
                    last = pe.sections[-1]
                    last_start = last.VirtualAddress
                    last_end = last_start + (last.Misc_VirtualSize or last.SizeOfRawData)
                    if last_start <= ep_rva < last_end:
                        matches.append(
                            PackerMatch(packer_id="unknown", confidence=0.6, method=self.name)
                        )
                if num_imports > 0 and num_imports < 5:
                    matches.append(
                        PackerMatch(packer_id="unknown", confidence=0.5, method=self.name)
                    )
            except Exception:
                pass
        elif elf is not None:
            try:
                entry = elf.header["e_entry"]
                load_segs = [
                    s for s in elf.iter_segments()
                    if s["p_type"] == "PT_LOAD" or s["p_type"] == PT_LOAD
                ]
                if load_segs:
                    last_seg = load_segs[-1]
                    start = last_seg["p_vaddr"]
                    end = start + last_seg["p_memsz"]
                    if start <= entry < end:
                        matches.append(
                            PackerMatch(packer_id="unknown", confidence=0.6, method=self.name)
                        )
            except Exception:
                pass

        return DetectionResult(
            matches=matches,
            is_packed=len(matches) > 0,
        )
