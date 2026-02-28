"""
Unpacker modules registry and dispatcher.
"""
from __future__ import annotations

from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.unpackers.upx import UPXUnpacker
from unpacker.unpackers.aspack import ASPackUnpacker
from unpacker.unpackers.mpress import MPRESSUnpacker
from unpacker.unpackers.themida import ThemidaUnpacker
from unpacker.unpackers.vmprotect import VMProtectUnpacker
from unpacker.unpackers.generic import GenericUnpacker


# Default set of unpackers; can be extended by registering more
_REGISTRY: list[BaseUnpacker] = [
    UPXUnpacker(),
    ASPackUnpacker(),
    MPRESSUnpacker(),
    ThemidaUnpacker(),
    VMProtectUnpacker(),
    GenericUnpacker(),
]


def register_unpacker(unpacker: BaseUnpacker) -> None:
    _REGISTRY.append(unpacker)


def get_unpacker_for(packer_id: str, sample_path: Path) -> BaseUnpacker | None:
    """Return the first unpacker that can_handle(packer_id, sample_path)."""
    for u in _REGISTRY:
        if u.can_handle(packer_id, sample_path):
            return u
    return None


def unpack_with_dispatcher(
    sample_path: Path,
    packer_id: str,
    options: UnpackOptions,
) -> UnpackResult:
    """Select unpacker by packer_id and run unpack."""
    unpacker = get_unpacker_for(packer_id, sample_path)
    if unpacker is None:
        unpacker = get_unpacker_for("generic", sample_path)
    if unpacker is None:
        return UnpackResult(
            success=False,
            error=f"No unpacker available for packer_id={packer_id}",
        )
    return unpacker.unpack(sample_path, options)


__all__ = [
    "BaseUnpacker",
    "UPXUnpacker",
    "ASPackUnpacker",
    "MPRESSUnpacker",
    "ThemidaUnpacker",
    "VMProtectUnpacker",
    "GenericUnpacker",
    "register_unpacker",
    "get_unpacker_for",
    "unpack_with_dispatcher",
]
