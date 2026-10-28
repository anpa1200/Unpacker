"""Artifact ownership, structural checks and optional known-original comparisons."""
from __future__ import annotations
import hashlib
from pathlib import Path


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()


def validate_artifact(sample, path, options, kind="decompressed_file"):
    import dataclasses
    from unpacker.static_worker import invoke
    settings=dataclasses.asdict(options);settings['output_dir']=str(options.output_dir.resolve())
    # Only validation's declared input crosses this boundary, not arbitrary extra state.
    settings['extra']={"reference":str(options.extra['reference'])} if options.extra.get('reference') else {}
    value,error=invoke(dict(operation="validate",sample=str(Path(sample).resolve()),path=str(Path(path).absolute()),settings=settings,kind=kind),min(10,options.timeout_seconds))
    if error:return "invalid",dict(artifact_kind=kind,complete_recovery="not_established",reason=error,
                                   static_analysis_failure=True,validation_timed_out="hard deadline" in error)
    if not isinstance(value,list) or len(value)!=2 or not isinstance(value[1],dict):
        return "invalid",dict(artifact_kind=kind,reason="Invalid static validation result",static_analysis_failure=True)
    return value[0],value[1]


def _validate_artifact_in_process(sample, path, options, kind="decompressed_file"):
    path, sample = Path(path), Path(sample)
    facts = {"artifact_kind": kind, "complete_recovery": "not_established"}
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(options.output_dir.resolve()):
        return "invalid", {**facts, "reason": "Output is not an owned regular file"}
    size = path.stat().st_size
    facts.update(output_size=size)
    if not 0 < size <= options.max_output_size_mb * 1024 * 1024:
        return "invalid", {**facts, "reason": "Empty or oversized output"}
    facts.update(input_sha256=sha256(sample), output_sha256=sha256(path))
    if facts["input_sha256"] == facts["output_sha256"]:
        return "invalid", {**facts, "reason": "Output unchanged from input"}
    if kind == "memory_snapshot":
        return "partial", {**facts, "reason": "Memory snapshot is not a reconstructed executable"}
    reference=options.extra.get("reference")
    if reference and (not Path(reference).is_file() or Path(reference).stat().st_size>options.max_input_size_mb*1024*1024):
        return "partial", {**facts,"reason":"Invalid or oversized known original"}
    data = path.read_bytes()
    if kind == "native_decompressed_file" and data.startswith(b"MZ"):
        import struct
        offset = struct.unpack_from("<I", data, 0x3c)[0] if len(data) >= 64 else len(data)
        if data[offset:offset+4] != b"PE\0\0":
            return "vendor_validated", {**facts, "format": "vendor_native_non_pe"}
    try:
        if data.startswith(b"MZ"):
            import pefile
            pe = pefile.PE(data=data, fast_load=False)
            try:
                ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                executable = [s for s in pe.sections if s.Characteristics & 0x20000000]
                imports = sorted((e.dll.lower(), i.name.decode("ascii","replace") if i.name else "#"+str(i.ordinal)) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in e.imports)
                facts.update(format="pe", machine=pe.FILE_HEADER.Machine, entry_point=ep, import_count=len(imports),
                             parser_warnings=pe.get_warnings()[:32])
                reference = options.extra.get("reference")
                comparison=None
                if reference:
                    reference_path=Path(reference)
                    if not reference_path.is_file() or reference_path.stat().st_size>options.max_input_size_mb*1024*1024:
                        return "partial", {**facts,"reason":"Invalid or oversized known original"}
                    from unpacker.reconstruction import compare_pe_reference
                    original=pefile.PE(str(reference_path),fast_load=False)
                    try: comparison=compare_pe_reference(pe,original)
                    finally: original.close()
                    facts['reconstruction_acceptance']=comparison
                    facts['known_original_code_imports_entry_match']=comparison['passed']
                if not executable or not any(s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in executable):
                    return "partial", {**facts, "reason": "Entry point is outside executable sections"}
                if any(s.SizeOfRawData and s.PointerToRawData + s.SizeOfRawData > len(data) for s in pe.sections):
                    return "invalid", {**facts, "reason": "Section raw data exceeds file"}
                if kind == "reconstructed_pe" and not imports:
                    return "partial", {**facts, "reason": "Emulated dump has no reconstructed imports"}
                if kind == "reconstructed_pe":
                    from unpacker.reconstruction import import_iat_consistency,import_descriptor_consistency
                    facts['import_descriptor_table']=import_descriptor_consistency(pe)
                    if not facts['import_descriptor_table']['passed']:
                        return 'partial',{**facts,'reason':'Reconstructed import descriptor table is incomplete'}
                    facts["iat_consistency"]=import_iat_consistency(pe)
                    if not facts["iat_consistency"]["passed"]:
                        return "partial", {**facts,"reason":"Reconstructed IAT is not loader-ready"}
                if comparison is not None:
                    if not comparison['passed']:
                        return "partial", {**facts,"reason":"Known-original reconstruction acceptance gates failed"}
                    return "known_answer_verified", facts
            finally: pe.close()
        elif data.startswith(b"\x7fELF"):
            import io
            from elftools.elf.elffile import ELFFile
            elf = ELFFile(io.BytesIO(data))
            load_segments = []
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    load_segments.append(seg)
                    if seg["p_filesz"] > seg["p_memsz"]:
                        return "invalid", {**facts, "reason": "ELF file segment exceeds memory size"}
                if seg["p_offset"] + seg["p_filesz"] > len(data):
                    return "invalid", {**facts, "reason": "ELF segment exceeds file"}
            facts.update(format="elf", machine=elf.header["e_machine"])
            if not load_segments:
                return "partial", {**facts, "reason": "ELF has no loadable segments"}
            entry = elf.header["e_entry"]
            if entry and not any(seg["p_flags"] & 1 and seg["p_vaddr"] <= entry < seg["p_vaddr"] + seg["p_memsz"] for seg in load_segments):
                return "partial", {**facts, "reason": "ELF entry point is outside executable segments"}
            if options.extra.get("reference"):
                facts["exact_original_sha256_match"] = sha256(options.extra["reference"]) == facts["output_sha256"]
                if facts["exact_original_sha256_match"]: return "known_answer_verified", facts
                return "partial", {**facts, "reason": "Known-original ELF hash differs"}
        elif kind != "native_decompressed_file":
            return "invalid", {**facts, "reason": "Unknown output format"}
        else:
            return "vendor_validated", facts
    except Exception as exc:
        return "invalid", {**facts, "reason": f"Output parser failed: {type(exc).__name__}"}
    return "structurally_valid", facts
