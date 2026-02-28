"""
Detect binary format (PE vs ELF) and load parsed object for detectors.
"""
from __future__ import annotations

from pathlib import Path

# Magic bytes
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"


def get_format(sample_path: Path) -> str | None:
    """Return 'pe', 'elf', or None if unknown/unreadable."""
    try:
        with open(sample_path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic.startswith(PE_MAGIC):
        return "pe"
    if magic.startswith(ELF_MAGIC):
        return "elf"
    return None


# PE optional header magic: 0x10b = PE32 (32-bit), 0x20b = PE32+ (64-bit)
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B


def load_pe(sample_path: Path):
    """Load PE; return pefile.PE or None."""
    try:
        import pefile
        return pefile.PE(str(sample_path), fast_load=True)
    except Exception:
        return None


def is_pe32_plus(sample_path: Path) -> bool:
    """Return True if the file is a PE32+ (64-bit) executable. False if PE32, not PE, or unreadable."""
    pe = load_pe(sample_path)
    if pe is None:
        return False
    try:
        return getattr(pe, "OPTIONAL_HEADER", None) and pe.OPTIONAL_HEADER.Magic == PE32_PLUS_MAGIC
    except Exception:
        return False


def load_elf(sample_path: Path):
    """Load ELF; return elftools.elf.elffile.ELFFile or None."""
    try:
        import io
        from elftools.elf.elffile import ELFFile
        data = sample_path.read_bytes()
        return ELFFile(io.BytesIO(data))
    except Exception:
        return None


def load_binary(sample_path: Path) -> tuple[object | None, object | None]:
    """Return (pe, elf); one will be None. Both None if format unknown or load failed."""
    fmt = get_format(sample_path)
    if fmt == "pe":
        return (load_pe(sample_path), None)
    if fmt == "elf":
        return (None, load_elf(sample_path))
    return (None, None)
