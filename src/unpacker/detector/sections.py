"""
Packer detection by known section names (UPX0/UPX1, .MPRESS1, .vmp0, etc.).
Supports both PE and ELF (UPX uses UPX0/UPX1 in ELF too).
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import DetectionResult, PackerMatch

# Map: tuple of section name substrings -> (packer_id, confidence)
# Match is case-insensitive for section names.
SECTION_RULES: list[tuple[tuple[str, ...], str, float]] = [
    (("UPX0", "UPX1"), "upx", 0.98),
    ((".MPRESS1", ".MPRESS2"), "mpress", 0.98),
    ((".vmp0", ".vmp1", ".vmp2"), "vmprotect", 0.95),
    (("ASPack", ".aspack", ".adata"), "aspack", 0.90),
    (("Themida",), "themida", 0.90),
    (("WinLicense",), "winlicense", 0.90),
    ((".enigma1", ".enigma2"), "enigma", 0.90),
    (("NSPack",), "nspack", 0.90),
]


def _get_section_names_pe(pe: object) -> list[str]:
    out: list[str] = []
    for sec in pe.sections:
        name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
        out.append(name)
    return out


def _get_section_names_elf(elf: object) -> list[str]:
    out: list[str] = []
    for sec in elf.iter_sections():
        out.append(sec.name or "")
    return out


class SectionDetector:
    """Detect packers by characteristic section names (PE and ELF)."""

    @property
    def name(self) -> str:
        return "sections"

    def detect(
        self,
        sample_path: Path,
        pe: object | None = None,
        elf: object | None = None,
    ) -> DetectionResult:
        section_names: list[str] = []
        if pe is not None:
            try:
                section_names = _get_section_names_pe(pe)
            except Exception:
                pass
        elif elf is not None:
            try:
                section_names = _get_section_names_elf(elf)
            except Exception:
                section_names = []
            # Many UPX-packed ELFs have stripped section headers; fallback: scan file for section-like UPX magic
            # Use UPX0/UPX1 only (not UPX!) to avoid false positives in unpacked files that contain "UPX!" in data
            if not any("UPX" in n for n in section_names):
                try:
                    data = sample_path.read_bytes()
                    if b"UPX0" in data or b"UPX1" in data:
                        section_names.append("UPX0")  # trigger UPX rule
                except OSError:
                    pass
        else:
            from unpacker.detector.format_ import load_binary
            pe, elf = load_binary(sample_path)
            if pe is not None:
                try:
                    section_names = _get_section_names_pe(pe)
                except Exception:
                    pass
            elif elf is not None:
                try:
                    section_names = _get_section_names_elf(elf)
                except Exception:
                    pass

        matches: list[PackerMatch] = []
        section_names_lower = [n.lower() for n in section_names]
        for substrings, packer_id, confidence in SECTION_RULES:
            if any(any(s.lower() in name for s in substrings) for name in section_names_lower):
                matches.append(PackerMatch(packer_id=packer_id, confidence=confidence, method=self.name))

        # PE fallback: some ASPack variants don't have .aspack section; check for aspack string in file
        if pe is not None and not any(m.packer_id == "aspack" for m in matches):
            try:
                data = sample_path.read_bytes()
                if b"ASPack" in data or b"aspack" in data or b".aspack" in data:
                    matches.append(PackerMatch(packer_id="aspack", confidence=0.75, method=self.name))
            except OSError:
                pass

        # PE fallback: VMProtect may use different section names; check for VMProtect / .vmp in file
        if pe is not None and not any(m.packer_id == "vmprotect" for m in matches):
            try:
                data = sample_path.read_bytes()
                if b"VMProtect" in data or b".vmp0" in data or b".vmp1" in data or b".vmp2" in data:
                    matches.append(PackerMatch(packer_id="vmprotect", confidence=0.75, method=self.name))
            except OSError:
                pass

        if not section_names and not matches:
            return DetectionResult(is_packed=False)

        return DetectionResult(
            matches=matches,
            is_packed=len(matches) > 0,
        )
