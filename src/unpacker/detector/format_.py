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


def parsed_architecture(pe=None, elf=None) -> str:
    """Use consistent parsed header fields, never a packer name or file suffix."""
    try:
        if pe is not None:
            return {(0x14C, PE32_MAGIC): "x86", (0x8664, PE32_PLUS_MAGIC): "x86_64",
                    (0xAA64, PE32_PLUS_MAGIC): "arm64"}.get((pe.FILE_HEADER.Machine, pe.OPTIONAL_HEADER.Magic), "unknown")
        if elf is not None:
            return {("EM_386", 32): "x86", ("EM_X86_64", 64): "x86_64",
                    ("EM_AARCH64", 64): "arm64"}.get((elf.header["e_machine"], elf.elfclass), "unknown")
    except (AttributeError, KeyError, TypeError):
        pass
    return "unknown"


def load_pe(sample_path: Path):
    """Load PE; return pefile.PE or None."""
    pe = None
    try:
        import pefile
        pe = pefile.PE(str(sample_path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        return pe
    except Exception:
        if pe is not None:
            pe.close()
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
    finally:
        pe.close()


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
