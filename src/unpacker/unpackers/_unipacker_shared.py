"""
Shared Unipacker emulation logic for ASPack, Themida, and other PE packers.
Patches Unipacker for robust dumping (safe memory read, survive fix_imports failure).
"""
from __future__ import annotations

import contextlib
import io
import threading
from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult

_PAGE = 0x1000
_PATCH_INSTALLED = False


def _safe_uc_mem_read(uc, base_addr: int, size: int) -> bytes:
    try:
        return uc.mem_read(base_addr, size)
    except Exception:
        pass
    data = bytearray(size)
    for off in range(0, size, _PAGE):
        chunk_len = min(_PAGE, size - off)
        try:
            chunk = uc.mem_read(base_addr + off, chunk_len)
            data[off : off + chunk_len] = chunk
        except Exception:
            pass
    return bytes(data)


def install_unipacker_patch() -> None:
    global _PATCH_INSTALLED
    if _PATCH_INSTALLED:
        return
    try:
        import unipacker.headers as headers
        from unipacker.imagedump import ImageDump
        from unicorn import UcError
    except ImportError:
        return

    _orig_pe_write = headers.pe_write

    class _SafePeWrite(_orig_pe_write):
        def __init__(self, uc, base_addr, total_size, filename, temporary=False):
            data = _safe_uc_mem_read(uc, base_addr, total_size)
            with open(filename, "wb+") as f:
                f.write(data)
            self.temporary = temporary
            self.filename = filename

    headers.pe_write = _SafePeWrite

    _orig_dump_image = ImageDump.dump_image

    def _dump_image_robust(self, uc, base_addr, virtualmemorysize, apicall_handler, sample, path="unpacked.exe"):
        ntp = apicall_handler.ntp
        dllname_to_functionlist = sample.dllname_to_functionlist
        if len(sample.allocated_chunks) == 0:
            total_size = virtualmemorysize
        else:
            total_size = sorted(sample.allocated_chunks)[-1][1] - base_addr
            virtualmemorysize = total_size

        try:
            from unipacker.headers import PE, pe_write
            from unipacker.utils import alignments
            from unicorn.x86_const import UC_X86_REG_EIP
        except ImportError:
            return _orig_dump_image(self, uc, base_addr, virtualmemorysize, apicall_handler, sample, path)

        try:
            hdr = PE(uc, base_addr)
        except Exception:
            return

        old_number_of_sections = hdr.pe_header.NumberOfSections
        hdr.opt_header.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP) - base_addr

        try:
            hdr = self.fix_imports(
                uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, sample.original_imports
            )
            if hdr is None:
                raise ValueError("fix_imports returned None")
        except (UcError, Exception):
            hdr.data_directories[1].VirtualAddress = 0
            hdr.data_directories[1].Size = 0

        hdr.data_directories[12].VirtualAddress = 0
        hdr.data_directories[12].Size = 0
        self.fix_sections(hdr, old_number_of_sections, virtualmemorysize)

        if (virtualmemorysize - 0xE000) <= hdr.data_directories[1].VirtualAddress <= virtualmemorysize or len(
            sample.allocated_chunks
        ) != 0 or True:
            pass
        else:
            virtualmemorysize -= 0x10000
            total_size = virtualmemorysize

        try:
            hdr.sync(uc)
        except Exception:
            pass
        hdr.opt_header.SizeOfImage = alignments(total_size, hdr.opt_header.SectionAlignment)
        hdr = self.fix_section_mem_protections(hdr, ntp)
        try:
            hdr.sync(uc)
            self.fix_checksum(uc, hdr, base_addr, total_size)
            hdr.sync(uc)
        except Exception:
            pass
        hdr.opt_header.DllCharacteristics = hdr.opt_header.DllCharacteristics & 0xFFBF
        try:
            hdr.sync(uc)
        except Exception:
            pass
        pe_write(uc, base_addr, total_size, path)

    ImageDump.dump_image = _dump_image_robust
    _PATCH_INSTALLED = True


def run_unipacker_emulation(
    sample_path: Path,
    out_path: Path,
    options: UnpackOptions,
    packer_label: str = "unipacker",
) -> UnpackResult:
    """Run Unipacker emulation on a PE; apply patch, then engine.emu(). Returns UnpackResult."""
    log: list[str] = []
    try:
        from unipacker.core import Sample, UnpackerEngine, SimpleClient
        from unipacker.utils import InvalidPEFile
    except ImportError as e:
        return UnpackResult(success=False, log=log, error=f"Unipacker import failed: {e}")

    try:
        sample = Sample(str(sample_path), auto_default_unpacker=True)
    except InvalidPEFile as e:
        return UnpackResult(success=False, log=log, error=f"Not a valid PE file: {e}")
    except Exception as e:
        return UnpackResult(success=False, log=[str(e)], error=str(e))

    log.append(f"Unipacker identified: {sample.unpacker.name}")
    install_unipacker_patch()

    event = threading.Event()
    client = SimpleClient(event)
    engine = UnpackerEngine(sample, str(out_path))
    engine.register_client(client)
    emu_error: list[str] = []

    def run_emu():
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                engine.emu()
            except Exception as e:
                emu_error.append(str(e))
            finally:
                event.set()

    thread = threading.Thread(target=run_emu, daemon=True)
    thread.start()
    signaled = event.wait(timeout=max(1.0, options.timeout_seconds))
    if not signaled:
        try:
            engine.stop()
        except Exception:
            pass
        thread.join(timeout=2.0)
        return UnpackResult(
            success=False,
            log=log,
            error=f"Unpacking timed out after {options.timeout_seconds}s",
        )

    thread.join(timeout=5.0)
    if emu_error:
        log.append(f"Emulation/dump error: {emu_error[0]}")

    if out_path.exists():
        return UnpackResult(success=True, output_path=out_path, log=log, metadata={"method": packer_label})

    for p in options.output_dir.iterdir():
        if not p.is_file():
            continue
        if "unpacked" in p.name and p.suffix != ".tmp" and p.stat().st_size > 0:
            return UnpackResult(success=True, output_path=p, log=log, metadata={"method": packer_label})
        if p.name.endswith(".unipacker_brokenimport.tmp") and p.stat().st_size > 0:
            final = p.with_suffix(sample_path.suffix)
            try:
                p.rename(final)
                return UnpackResult(
                    success=True,
                    output_path=final,
                    log=log + ["Used Unipacker broken-import dump"],
                    metadata={"method": packer_label + "_brokenimport"},
                )
            except OSError:
                pass

    err = emu_error[0] if emu_error else "Unipacker finished but no output file found"
    return UnpackResult(success=False, log=log, error=err)


def unipacker_available() -> bool:
    try:
        from unipacker.core import Sample, UnpackerEngine, SimpleClient  # noqa: F401
        return True
    except Exception:
        return False
