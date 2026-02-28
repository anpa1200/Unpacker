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


def load_pe(sample_path: Path):
    """Load PE; return pefile.PE or None."""
    try:
        import pefile
        return pefile.PE(str(sample_path), fast_load=True)
    except Exception:
        return None


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
