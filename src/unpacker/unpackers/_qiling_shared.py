"""Explicit x86-64 rootfs selection and supervised partial memory snapshots."""
from pathlib import Path
import os
from unpacker.types import UnpackResult


def qiling_available():
    try:
        from qiling import Qiling
        return True
    except Exception:
        return False


def _find_rootfs(arch="x8664", root=None):
    value = root or os.environ.get("QILING_ROOTFS")
    if not value: return None
    base = Path(value).expanduser()
    for path in (base / f"{arch}_windows", base):
        if path.name in {"x86_windows","x8664_windows"} and path.name != f"{arch}_windows":
            continue
        if path.is_dir() and any((path/sub).is_file() for sub in ("dlls/kernel32.dll","Windows/System32/kernel32.dll")):
            return path.resolve()
    return None


def run_qiling_emulation(sample_path,out_path,options,packer_label="qiling"):
    if not options.allow_emulation:
        return UnpackResult(False,error="Emulation requires explicit opt-in inside isolation",status="unsupported")
    root = _find_rootfs("x8664",options.extra.get("rootfs"))
    if root is None:
        return UnpackResult(False,error="Explicit x8664 Windows rootfs with kernel32.dll required",status="dependency_error")
    from dataclasses import replace
    from unpacker.backend_worker import supervise
    options=replace(options,extra={**options.extra,"rootfs":str(root)})
    return supervise("qiling",sample_path,out_path,options,packer_label)


def _run_qiling_in_process(sample_path,out_path,options,packer_label):
    from unpacker.detector.format_ import load_pe
    pe=load_pe(sample_path)
    if pe is None: return UnpackResult(False,error="Valid PE required",status="unsupported")
    try:
        if pe.FILE_HEADER.Machine!=0x8664 or pe.OPTIONAL_HEADER.Magic!=0x20b:
            return UnpackResult(False,error="Qiling path requires x86-64 PE32+",status="unsupported")
        image_base,size=pe.OPTIONAL_HEADER.ImageBase,pe.OPTIONAL_HEADER.SizeOfImage
    finally: pe.close()
    if not 0<size<=options.max_output_size_mb*1024*1024:
        return UnpackResult(False,error="Image size exceeds dump budget")
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    ql=None
    missing=[]
    error=None
    try:
        ql=Qiling([str(sample_path)],options.extra["rootfs"],verbose=QL_VERBOSE.OFF)
        # Qiling/Unicorn timeout is microseconds; outer supervisor owns wall time.
        try: ql.run(timeout=int(options.timeout_seconds*1_000_000))
        except Exception as exc: error=type(exc).__name__
        base=getattr(ql.loader,"pe_image_address",None) or image_base
        data=bytearray(size)
        for off in range(0,size,4096):
            n=min(4096,size-off)
            try: data[off:off+n]=ql.mem.read(base+off,n)
            except Exception: missing.append([off,n])
        if not any(data):
            return UnpackResult(False,error="All-zero snapshot rejected")
        out_path.write_bytes(data)
        return UnpackResult(False,output_path=out_path,status="partial",artifact_kind="memory_snapshot",
            validation_status="partial",error="Snapshot extraction does not establish unpacking completion",
            warnings=["Memory layout; no PE reconstruction or completeness verification"],
            metadata={"method":packer_label,"missing_ranges":missing[:1024],"emulation_error":error,
                      "complete_recovery":"not_established"})
    finally:
        if ql is not None: ql.stop()
