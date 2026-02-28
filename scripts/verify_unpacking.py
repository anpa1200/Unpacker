#!/usr/bin/env python3
"""
Verify that unpacking succeeded: check unpacked files exist, have valid magic,
are larger than originals, and (optionally) are no longer detected as packed.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add src for unpacker imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"


def get_format(path: Path) -> str | None:
    try:
        magic = path.read_bytes()[:4]
        if magic.startswith(PE_MAGIC):
            return "pe"
        if magic.startswith(ELF_MAGIC):
            return "elf"
    except OSError:
        pass
    return None


def main() -> int:
    unpacked_dir = Path(__file__).resolve().parents[1] / "unpacked" / "upx"
    samples_dir = Path(__file__).resolve().parents[1] / "samples_by_packer" / "upx"

    if not unpacked_dir.exists():
        print("No unpacked/upx directory found. Run the pipeline first.")
        return 1

    unpacked_files = sorted(unpacked_dir.iterdir()) if unpacked_dir.is_dir() else []
    if not unpacked_files:
        print("No files in unpacked/upx.")
        return 1

    from unpacker.detector import DetectorPipeline
    pipeline = DetectorPipeline(confidence_threshold=0.5)

    all_ok = True
    print("Unpacking verification\n" + "=" * 60)

    for unp in unpacked_files:
        if not unp.is_file():
            continue
        # Map unpacked name back to original (strip .unpacked.upx.*)
        stem = unp.stem
        if ".unpacked.upx" in stem:
            orig_stem = stem.replace(".unpacked.upx", "")
        else:
            orig_stem = stem
        # Find original in samples (could be .exe or .bin)
        orig = None
        for ext in (".exe", ".bin"):
            candidate = samples_dir / f"{orig_stem}{ext}"
            if candidate.exists():
                orig = candidate
                break
        if not orig or not orig.exists():
            orig = None

        fmt = get_format(unp)
        size_ok = True
        if orig and orig.exists():
            orig_size = orig.stat().st_size
            unp_size = unp.stat().st_size
            size_ok = unp_size > orig_size  # unpacked should be larger
            size_msg = f"size {orig_size} -> {unp_size} ({'OK' if size_ok else 'check'})"
        else:
            size_msg = f"size {unp.stat().st_size} (no original to compare)"

        detection = pipeline.detect(unp)
        still_packed = detection.is_packed and detection.best_packer_id == "upx"
        pack_msg = "not packed" if not still_packed else "still detected as UPX (false positive possible)"

        ok = fmt and size_ok and not still_packed
        if not ok:
            all_ok = False

        print(f"\n{unp.name}")
        print(f"  format: {fmt or 'unknown'}")
        print(f"  {size_msg}")
        print(f"  detector: {pack_msg}")
        print(f"  result: {'PASS' if ok else 'CHECK'}")

    print("\n" + "=" * 60)
    print("Overall:", "PASS" if all_ok else "See CHECK(s) above")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
