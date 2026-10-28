"""
Unpacker — Modular malware packer detection and unpacking.
"""
__version__ = "1.2.0rc12"

from unpacker.types import (
    DetectionResult,
    PackerMatch,
    UnpackOptions,
    UnpackResult,
)

__all__ = [
    "__version__",
    "DetectionResult",
    "PackerMatch",
    "UnpackOptions",
    "UnpackResult",
]
