#!/usr/bin/env python3
"""Run unpacker CLI (adds src to path when not installed)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unpacker.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
