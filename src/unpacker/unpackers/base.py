"""
Base interface for unpacker modules.
"""
from __future__ import annotations

from pathlib import Path
from abc import ABC, abstractmethod

from unpacker.types import UnpackOptions, UnpackResult


class BaseUnpacker(ABC):
    """Interface that every packer-specific unpacker module must implement."""

    @property
    @abstractmethod
    def packer_id(self) -> str:
        """Packer identifier this module handles (e.g. 'upx', 'aspack')."""
        ...

    def can_handle(self, packer_id: str, sample_path: Path) -> bool:
        """Return True if this module can unpack the given packer / file."""
        return packer_id.lower() == self.packer_id.lower()

    @abstractmethod
    def unpack(self, sample_path: Path, options: UnpackOptions) -> UnpackResult:
        """Unpack the sample. Return UnpackResult with output path or buffer and log."""
        ...
