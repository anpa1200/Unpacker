"""Content-only detection: parsing failure and no packing evidence are distinct."""
from __future__ import annotations
import math
from pathlib import Path
from unpacker.detector.entropy import EntropyDetector
from unpacker.detector.format_ import load_binary, get_format, parsed_architecture
from unpacker.detector.heuristics import HeuristicsDetector
from unpacker.detector.sections import SectionDetector
from unpacker.detector.signatures import SignatureDetector
from unpacker.types import DetectionResult, PackerMatch


def _merge_results(results, confidence_threshold, sample_path=None):
    matches = [m for r in results for m in r.matches if m.confidence >= confidence_threshold]
    return DetectionResult(matches=matches, is_packed=bool(matches),
                           errors=[e for r in results for e in r.errors])


class DetectorPipeline:
    def __init__(self, confidence_threshold=.5, use_signatures=True, use_sections=True,
                 use_entropy=True, use_heuristics=True, signatures_dir=None,
                 use_native_upx=True, max_input_size_mb=32, static_timeout_seconds=10):
        if not math.isfinite(confidence_threshold) or not 0 <= confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be between 0 and 1")
        if not math.isfinite(static_timeout_seconds) or static_timeout_seconds <= 0:
            raise ValueError("Invalid static deadline")
        self.static_timeout_seconds = static_timeout_seconds
        self._settings = dict(confidence_threshold=confidence_threshold,use_signatures=use_signatures,
            use_sections=use_sections,use_entropy=use_entropy,use_heuristics=use_heuristics,
            signatures_dir=str(signatures_dir) if signatures_dir is not None else None,
            use_native_upx=use_native_upx,max_input_size_mb=max_input_size_mb)
        if signatures_dir is not None: signatures_dir=Path(signatures_dir)
        self.confidence_threshold = confidence_threshold
        self.use_native_upx = use_native_upx
        self.max_bytes = max_input_size_mb * 1024 * 1024
        self._methods = []
        if use_signatures: self._methods.append(SignatureDetector(signatures_dir))
        if use_sections: self._methods.append(SectionDetector())
        if use_entropy: self._methods.append(EntropyDetector())
        if use_heuristics: self._methods.append(HeuristicsDetector())

    def detect(self, sample_path: Path, pe=None, elf=None):
        if pe is not None or elf is not None:
            # Advanced caller-owned parser objects cannot cross the JSON boundary.
            # This path does no owned parsing and remains explicitly low-level.
            return self._detect_in_process(sample_path,pe,elf)
        from unpacker.static_worker import invoke
        value,error=invoke(dict(operation="detect",sample=str(Path(sample_path).resolve()),settings=self._settings),self.static_timeout_seconds)
        if error:return DetectionResult(status="inconclusive",errors=[error])
        try:
            value['matches']=[PackerMatch(**match) for match in value['matches']]
            return DetectionResult(**value)
        except (KeyError,TypeError,ValueError):
            return DetectionResult(status="inconclusive",errors=["Invalid static detector result"])

    def _detect_in_process(self, sample_path: Path, pe=None, elf=None):
        sample_path = Path(sample_path)
        try:
            if not sample_path.is_file():
                return DetectionResult(status="input_error", errors=["Input is not a regular file"])
            if sample_path.stat().st_size > self.max_bytes:
                return DetectionResult(status="input_error", errors=["Input exceeds size limit"])
            data = sample_path.read_bytes()
        except OSError:
            return DetectionResult(status="input_error", errors=["Input is unreadable"])
        fmt = get_format(sample_path)
        owned = pe is None and elf is None
        if owned: pe, elf = load_binary(sample_path)
        results = []
        if elf is not None:
            from unpacker.elf_notes import note_payload
            try:
                note_payload(data,self.max_bytes)
                results.append(DetectionResult(matches=[PackerMatch('elf_note',.95,'appended_elf_note_structure')]))
            except Exception:
                # Ordinary ELF notes are not containers; other methods still run.
                pass
            if b'main.runFromMemory' in data:
                from unpacker.unpackers.ezuri import ezuri_layout
                try:
                    ezuri_layout(data)
                    results.append(DetectionResult(matches=[PackerMatch('ezuri',.9,'ezuri_appended_trailer_structure')]))
                except Exception:pass
        if data.startswith(b"#!/bin/sh") and b"gzip" in data[:4096] and b"tail" in data[:4096] and b"\x1f\x8b\x08" in data:
            results.append(DetectionResult(matches=[PackerMatch("gzexe", .9, "gzip_wrapper_structure")]))
        native_upx = False
        native_not_packed = False
        if self.use_native_upx and b"UPX!" in data:
            from unpacker.process import run_command
            import shutil
            tool = shutil.which("upx")
            if tool:
                probe = run_command([tool, "-t", str(sample_path.resolve())], timeout=5, max_output_mb=1, start_new_session=False)
                native_upx = probe["returncode"] == 0 and not probe["timed_out"]
                diagnostic = (probe.get("stdout", "") + probe.get("stderr", "")).lower()
                native_not_packed = not probe["timed_out"] and ("notpackedexception" in diagnostic or "not packed by upx" in diagnostic)
                if native_upx:
                    results.append(DetectionResult(matches=[PackerMatch("upx", 1.0, "native_integrity")]))
        try:
            if pe is not None or elf is not None:
                for method in self._methods:
                    try:
                        results.append(method.detect(sample_path, pe=pe, elf=elf))
                    except Exception as exc:
                        results.append(DetectionResult(errors=[f"{getattr(method, 'name', type(method).__name__)}: {type(exc).__name__}"]))
            merged = _merge_results(results, self.confidence_threshold)
            if native_not_packed:
                merged.matches = [m for m in merged.matches if m.packer_id != "upx"]
                merged.is_packed = bool(merged.matches)
            merged.format = fmt
            merged.architecture = parsed_architecture(pe, elf)
            if native_upx or any(m.packer_id == "gzexe" for r in results for m in r.matches):
                merged.status = "analyzed" if fmt else "native_format"
            elif fmt is None:
                merged.status = "unsupported_format"
            elif pe is None and elf is None:
                merged.status = "parse_error"
                merged.errors.append("Format recognized but parser could not load it")
            elif merged.errors:
                merged.status = "inconclusive"
            else:
                merged.status = "analyzed"
            return merged
        finally:
            if owned and pe is not None: pe.close()
