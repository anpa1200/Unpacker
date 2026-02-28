"""
Optional PE rebuilder: IAT reconstruction, header fixes (PE-sieve-style).
"""
from unpacker.pe_rebuilder.iat import rebuild_iat

__all__ = ["rebuild_iat"]
