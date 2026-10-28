"""Hard-deadline child process for emulators. Run the tool in an OS sandbox/VM."""
from __future__ import annotations
import contextlib, dataclasses, json, sys
from pathlib import Path
from unpacker.types import UnpackOptions, UnpackResult
from unpacker.process import run_command


def _progress_metadata(directory):
    path=Path(directory)/'.emulation-progress.json'
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size>16384:return {}
        data=json.loads(path.read_text())
        if not isinstance(data,dict) or type(data.get('instructions')) is not int or data['instructions']<0:return {}
        return {'worker_progress':{key:data[key] for key in ['instructions','last_address','api_calls','sections_executed','cpu_state','write_tracking','module_handles'] if key in data}}
    except (OSError,ValueError,TypeError):return {}


def supervise(backend, sample, out, options, label):
    if out.exists() or out.is_symlink():
        return UnpackResult(False, error="Output collision")
    payload = dict(backend=backend,sample=str(sample.resolve()),out=str(out.resolve()),label=label,
                   output_dir=str(options.output_dir.resolve()),timeout=options.timeout_seconds,
                   max_output=options.max_output_size_mb,max_input=options.max_input_size_mb,
                   max_total_output=options.max_total_output_size_mb,max_entries=options.max_output_entries,extra=options.extra)
    # Only an explicit rootfs setting is forwarded; no API keys/parent environment.
    package_root = str(Path(__file__).resolve().parents[1])
    code = "import sys;sys.path.insert(0,"+repr(package_root)+");from unpacker.backend_worker import main;main()"
    process = run_command([sys.executable,"-I","-B","-c",code],timeout=options.timeout_seconds,
                           max_output_mb=options.max_output_size_mb,cwd=options.output_dir,
                           input_text=json.dumps(payload),output_root=options.extra.get("output_budget_root",options.output_dir),
                           max_total_output_mb=options.max_total_output_size_mb,max_output_entries=options.max_output_entries)
    if process.get("output_limit_exceeded"):
        return UnpackResult(False,error=process["output_limit_exceeded"],status="resource_limit",artifact_kind="partial_dump",log=[process["stderr"]])
    if process["timed_out"]:
        return UnpackResult(False,output_path=out if out.is_file() else None,error="Emulation hard deadline exceeded",status="timeout",artifact_kind="partial_dump",log=[process['stderr']],metadata=_progress_metadata(options.output_dir))
    if process["returncode"] != 0:
        return UnpackResult(False,output_path=out if out.is_file() else None,error="Emulation worker exited abnormally",status="backend_error",artifact_kind="partial_dump",log=[process['stderr']],metadata={'worker_exit_code':process['returncode']})
    try:
        result=json.loads(process["stdout"])
        if result.get("output_path"): result["output_path"]=Path(result["output_path"])
        return UnpackResult(**result)
    except (ValueError,TypeError):
        return UnpackResult(False,error="Invalid emulator worker result",status="backend_error")


class BoundedLog:
    def __init__(self): self.text="";self.forwarded=0
    def write(self,text):
        self.text=(self.text+text)[-12000:]
        remaining=max(0,12000-self.forwarded)
        if remaining:
            sys.__stderr__.write(text[:remaining]);sys.__stderr__.flush()
            self.forwarded+=min(len(text),remaining)
        return len(text)
    def flush(self): pass


def _options_from_payload(payload):
    from unpacker.deadlines import positive_seconds
    return UnpackOptions(Path(payload["output_dir"]),timeout_seconds=positive_seconds(payload["timeout"]),
        max_output_size_mb=payload["max_output"],max_input_size_mb=payload["max_input"],
        max_total_output_size_mb=payload["max_total_output"],max_output_entries=payload["max_entries"],
        extra=payload["extra"],allow_emulation=True)


def main():
    payload=json.loads(sys.stdin.read(65537))
    options=_options_from_payload(payload)
    log=BoundedLog()
    try:
        with contextlib.redirect_stdout(log),contextlib.redirect_stderr(log):
            if payload["backend"]=="unipacker":
                from unpacker.unpackers._unipacker_shared import _run_unipacker_in_process
                result=_run_unipacker_in_process(Path(payload["sample"]),Path(payload["out"]),options,payload["label"])
            elif payload["backend"]=="enigma_static":
                from unpacker.unpackers.enigma import _extract_core
                result=_extract_core(Path(payload["sample"]),Path(payload["out"]),options)
            elif payload["backend"]=="elf_note_static":
                from unpacker.unpackers.elf_note import _extract_note
                result=_extract_note(Path(payload["sample"]),Path(payload["out"]),options)
            elif payload["backend"]=="ezuri_static":
                from unpacker.unpackers.ezuri import _extract_ezuri
                result=_extract_ezuri(Path(payload["sample"]),Path(payload["out"]),options)
            elif payload["backend"]=="pakkero_static":
                from unpacker.unpackers.pakkero import _extract_pakkero
                result=_extract_pakkero(Path(payload["sample"]),Path(payload["out"]),options)
            elif payload["backend"]=="qiling":
                from unpacker.unpackers._qiling_shared import _run_qiling_in_process
                result=_run_qiling_in_process(Path(payload["sample"]),Path(payload["out"]),options,payload["label"])
            else: result=UnpackResult(False,error="Unknown internal backend")
    except BaseException as exc:
        result=UnpackResult(False,error=f"Emulator initialization failed: {type(exc).__name__}",status="backend_error")
    if log.text:result.log.append(log.text)
    data=dataclasses.asdict(result)
    if data["output_path"]:data["output_path"]=str(data["output_path"])
    print(json.dumps(data))
