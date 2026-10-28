"""Allowlist projection of an existing report. Never opens or executes a sample.

Reports are untrusted claims. Preserve missing checks as not_checked; never infer
backend readiness, architecture, original recovery or validator success from names.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path

from .config import AIError
from .contracts import EvidenceBundle
from .run_contracts import ReportProvenance, RunEvidenceBundle

REPORT_LIMIT = 2 * 1024 * 1024
PARTIAL_REASONS = {
    "Entry section execute permission inferred from emulator handoff; recovery remains partial": "entry_execute_inferred",
    "Noncontiguous live allocations are outside the reconstructed image": "noncontiguous_allocations_omitted",
    "Live PE headers were erased; section layout restored from input metadata": "headers_inferred",
    "Instruction-cache flush approximated by backend memory-write behavior": "instruction_cache_approximated",
    "Erased import names recovered from observed guest IAT bindings": "erased_import_names_recovered",
    "MessageBox response selected by noninteractive model": "interactive_response_modeled",
}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw: bytes):
    def nonfinite(_):
        raise ValueError("Nonfinite JSON number")
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Nonfinite JSON number")
        return number
    return json.loads(raw, object_pairs_hook=_object, parse_constant=nonfinite, parse_float=finite_float)


def read_regular(path: Path, limit: int) -> bytes:
    # O_NONBLOCK prevents a FIFO blocking before fstat; reject a symlink file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise AIError("input_not_regular_file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise AIError("input_budget_exceeded")
    return raw


def load_evidence(raw: bytes):
    data = strict_json(raw)
    cls = RunEvidenceBundle if isinstance(data, dict) and data.get("schema_version") == "2" else EvidenceBundle
    return cls.model_validate(data)


def _dict(value):
    return value if isinstance(value, dict) else {}


def _enum(value, choices, default):
    return value if isinstance(value, str) and value in choices else default


def collect_report(raw: bytes) -> tuple[RunEvidenceBundle, ReportProvenance]:
    if len(raw) > REPORT_LIMIT:
        raise AIError("input_budget_exceeded")
    data = strict_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("detection"), dict) or not isinstance(data.get("layers"), list):
        raise AIError("invalid_run_report")
    if len(data["layers"]) > 32:
        raise AIError("report_layer_budget_exceeded")
    detection = data["detection"]
    fmt = _enum(detection.get("format"), {"pe", "elf"}, "unknown")
    arch = _enum(detection.get("architecture"), {"x86", "x86_64", "arm64"}, "unknown")
    detection_status = _enum(detection.get("status"), {"analyzed", "unsupported_format", "native_format", "parse_error", "inconclusive", "input_error"}, "parse_error")
    parsed = "parsed" if detection_status == "analyzed" and fmt != "unknown" else "error"
    if detection_status in {"unsupported_format", "native_format"}:
        parsed = "unsupported"
    observations = []
    # Only exact section matches have this meaning. Entropy detector confidence
    # is not entropy, and native integrity is not a section-name observation.
    signals = {"upx": "upx_sections", "aspack": "aspack_sections", "vmprotect": "vmprotect_sections", "themida": "themida_sections"}
    seen = set()
    matches = detection.get("matches", [])
    if isinstance(matches, list):
        for match in matches[:64]:
            match = _dict(match)
            packer = match.get("packer_id")
            if isinstance(packer, str) and packer in signals and match.get("method") == "sections" and packer not in seen:
                observations.append(dict(id=f"signal.{len(observations)+1}", kind="packing_signal", signal=signals[packer]))
                seen.add(packer)
    runs = []
    for index, layer in enumerate(data["layers"], 1):
        if not isinstance(layer, dict) or not isinstance(layer.get("unpack_result"), dict):
            raise AIError("invalid_run_report")
        result = layer["unpack_result"]
        meta = _dict(result.get("metadata"))
        method = meta.get("method")
        backend = "unknown"
        if isinstance(method, str):
            if method.startswith("unipacker_"): backend = "unipacker"
            elif method.startswith("qiling_"): backend = "qiling"
            elif method in {"upx_native", "native_upx"}: backend = "upx_native"
            elif method in {"gzip_wrapper_static", "elf_note_static", "ezuri_static", "enigma_retained_core_static"}: backend = "static"
        acceptance = _dict(meta.get("reconstruction_acceptance"))
        source_gates = _dict(acceptance.get("gates"))
        # Gates originate in the reference comparison, not the status/success flag.
        has_pe_reference = bool(source_gates) and acceptance.get("scope") == "code_imports_entry_static_only"
        exact = meta.get("exact_original_sha256_match")
        exact_match = "passed" if exact is True else "failed" if exact is False else "not_checked"
        has_reference = has_pe_reference or type(exact) is bool
        gates = {name: ("passed" if source_gates.get(name) is True else "failed" if source_gates.get(name) is False else "not_checked")
                 for name in ("executable_bytes", "entry_rva", "entry_mapping", "imports", "iat_loader_ready", "import_descriptors", "machine")} if has_pe_reference else {}
        rejected = meta.get("rejected_handoffs", [])
        if not isinstance(rejected, list) or len(rejected) > 64:
            raise AIError("invalid_handoff_evidence")
        unsupported = _dict(meta.get("api_model")).get("unsupported", [])
        if not isinstance(unsupported, list) or len(unsupported) > 32:
            raise AIError("invalid_runtime_evidence")
        names = {_enum(_dict(item).get("name"), {"GetDC", "CreateEventA"}, "other") for item in unsupported}
        message = _dict(_dict(meta.get("last_guest_message")).get("text"))
        guest_error = "none"
        if type(meta.get("guest_exit_code")) is int:
            guest_error = "exit_before_handoff"
        if message.get("value") == "Corrupt Data!" and message.get("truncated") is False:
            guest_error = "corrupt_data_reported"
        failure = "none"
        error = result.get("error")
        if isinstance(error, str):
            if error.startswith("Unmapped emulated memory access:"):
                failure = "unmapped_access"
            for marker, label in (("UC_ERR_READ_UNMAPPED", "unmapped_read"), ("UC_ERR_FETCH_UNMAPPED", "unmapped_fetch"),
                                  ("UC_ERR_WRITE_PROT", "write_protected"), ("UC_ERR_READ_PROT", "read_protected"), ("UC_ERR_FETCH_PROT", "fetch_protected"),
                                  ("UC_ERR_INSN_INVALID", "invalid_instruction"), ("UC_ERR_EXCEPTION", "cpu_exception")):
                if marker in error:
                    failure = label
                    break
        outcome = _enum(result.get("status"), {"extracted", "extracted_vendor_format", "partial", "failed", "timeout", "unsupported"}, "unknown")
        causes = set()
        if outcome == "partial":
            repairs = meta.get("repairs", [])
            if not isinstance(repairs, list) or len(repairs) > 64:
                raise AIError("invalid_partial_evidence")
            for repair in repairs:
                causes.add(PARTIAL_REASONS.get(repair, "other") if isinstance(repair, str) else "other")
            if error == "Embedded virtual filesystem and wrapper TLS behavior are not reconstructed":
                causes.add("embedded_vfs_tls_unreconstructed")
            if not causes:
                causes.add("other")
        runs.append(dict(id=f"layer.{index}", backend=backend,
            reported_outcome=outcome, partial_causes=sorted(causes),
            validation=_enum(result.get("validation_status"), {"structurally_valid", "known_answer_verified", "vendor_validated", "invalid", "partial", "not_checked"}, "not_checked"),
            gates=gates, reference="provided" if has_reference else "not_established",
            exact_original_match=exact_match, rejected_handoffs=len(rejected), runtime_gaps=sorted(names), guest_error=guest_error, observed_failure=failure))
    evidence = RunEvidenceBundle.model_validate(dict(format=fmt, architecture=arch, parse_status=parsed, observations=observations, runs=runs))
    return evidence, ReportProvenance(report_sha256=hashlib.sha256(raw).hexdigest(), report_bytes=len(raw))
