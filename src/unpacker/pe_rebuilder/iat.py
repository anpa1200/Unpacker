"""
IAT reconstruction: unerase / rebuild (stub; can wrap PE-sieve /imp or implement later).
"""
from __future__ import annotations

from pathlib import Path


def rebuild_iat(pe_path: Path, mode: str = "auto") -> bool:
    """
    Rebuild or unerase Import Table. mode: 'none'|'unerase'|'rebuild_r0'|'rebuild_r1'|'rebuild_r2'|'auto'.
    Returns True if successful.
    """
    # TODO: Call PE-sieve with /imp N|U|R0|R1|R2|A or implement minimal IAT discovery
    return False
