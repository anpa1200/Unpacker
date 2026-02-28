"""
Shared Qiling emulation for PE32+ (64-bit) unpacking.
Used when Unipacker cannot run (Unipacker is PE32-only).
Requires: pip install qiling; Windows rootfs for x8664 (see README).
"""
from __future__ import annotations

import contextlib
import io
import os
import threading
from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult


def qiling_available() -> bool:
    """Return True if Qiling can be imported."""
    try:
        from qiling import Qiling  # noqa: F401
        return True
    except Exception:
        return False


def _find_rootfs(arch: str = "x8664") -> Path | None:
    """Find Windows rootfs for Qiling. arch is 'x8664' or 'x86'."""
    # 1) Explicit env
    env_root = os.environ.get("QILING_ROOTFS")
    if env_root:
        p = Path(env_root)
        if p.is_dir():
            return p
        # May point to arch-specific subdir
        for sub in (f"{arch}_windows", "x8664_windows", "x86_windows"):
            cand = p / sub
            if cand.is_dir():
                return cand
    # 2) Next to qiling package
    try:
        import qiling
        pkg_dir = Path(qiling.__file__).resolve().parent
        for sub in ("examples/rootfs", "rootfs", "../rootfs"):
            cand = (pkg_dir / sub).resolve()
            for name in (f"{arch}_windows", "x8664_windows", "x86_windows"):
                d = cand / name
                if d.is_dir():
                    return d
    except Exception:
        pass
    # 3) Cwd / common locations
    for base in (Path.cwd(), Path.home() / ".local" / "share" / "qiling"):
        for name in (f"{arch}_windows", "x8664_windows", "x86_windows"):
            d = base / "rootfs" / name if (base / "rootfs").is_dir() else base / name
            if d.is_dir():
                return d
    return None


def run_qiling_emulation(
    sample_path: Path,
    out_path: Path,
    options: UnpackOptions,
    packer_label: str = "qiling",
) -> UnpackResult:
    """Run Qiling emulation on a PE32+ sample, then dump memory to out_path. Returns UnpackResult."""
    log: list[str] = []
    if not sample_path.exists():
        return UnpackResult(success=False, log=log, error=f"File not found: {sample_path}")

    try:
        from unpacker.detector.format_ import load_pe, is_pe32_plus
    except Exception as e:
        return UnpackResult(success=False, log=log, error=f"Cannot load format: {e}")

    if not is_pe32_plus(sample_path):
        return UnpackResult(
            success=False,
            log=log,
            error="Qiling path is for PE32+ (64-bit) only. Use Unipacker path for PE32.",
        )

    pe = load_pe(sample_path)
    if pe is None:
        return UnpackResult(success=False, log=log, error="Not a valid PE file.")
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    except Exception:
        return UnpackResult(success=False, log=log, error="Could not read PE ImageBase/SizeOfImage.")
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except ImportError as e:
        return UnpackResult(
            success=False,
            log=log,
            error=f"Qiling not installed. Install with: pip install qiling. Details: {e}",
        )

    rootfs = _find_rootfs("x8664")
    if rootfs is None:
        return UnpackResult(
            success=False,
            log=log,
            error=(
                "Qiling Windows rootfs not found. Set QILING_ROOTFS to a directory containing "
                "x8664_windows (with Windows DLLs). See https://github.com/qilingframework/rootfs"
            ),
        )

    log.append(f"Using rootfs: {rootfs}")
    emu_error: list[str] = []
    done = threading.Event()
    dump_ok: list[bool] = [False]

    def run_and_dump():
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            ql = None
            try:
                ql = Qiling(
                    [str(sample_path)],
                    str(rootfs),
                    verbose=QL_VERBOSE.OFF,
                )
                # Run with timeout (Qiling 1.x: timeout in ms, or use run(begin=..., end=...) for steps)
                run_timeout_us = int(options.timeout_seconds * 1_000_000)
                try:
                    ql.run(timeout=run_timeout_us)
                except Exception as e:
                    emu_error.append(str(e))
                # Dump memory after run (packed or partially unpacked)
                base = getattr(ql.loader, "pe_image_address", None)
                if base is None and getattr(ql.loader, "images", None):
                    base = ql.loader.images[0].base if ql.loader.images else None
                if base is None:
                    base = image_base
                size = getattr(ql.loader, "pe_image_address_size", None) or size_of_image
                size = min(size, size_of_image + 0x10000)
                try:
                    data = ql.mem.read(base, size)
                except Exception:
                    data = bytearray()
                    for off in range(0, size, 0x1000):
                        try:
                            data.extend(ql.mem.read(base + off, min(0x1000, size - off)))
                        except Exception:
                            data.extend(b"\x00" * min(0x1000, size - off))
                    data = bytes(data)
                if len(data) >= 0x1000:
                    out_path.write_bytes(data)
                    dump_ok[0] = True
            except Exception as e:
                emu_error.append(str(e))
            finally:
                if ql is not None:
                    try:
                        ql.stop()
                    except Exception:
                        pass
                done.set()

    thread = threading.Thread(target=run_and_dump, daemon=True)
    thread.start()
    done.wait(timeout=options.timeout_seconds + 30.0)
    if emu_error:
        log.append(f"Emulation note: {emu_error[0][:200]}")

    if dump_ok[0] and out_path.exists():
        return UnpackResult(
            success=True,
            output_path=out_path,
            log=log,
            metadata={"method": packer_label},
        )
    return UnpackResult(
        success=False,
        log=log,
        error=emu_error[0] if emu_error else "Qiling ran but could not dump memory (check rootfs and loader).",
    )
