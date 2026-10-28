"""Version 2: bounded run diagnosis; no sample content or execution authority."""
from __future__ import annotations

from typing import Annotated, Literal
from pydantic import Field, model_validator
from .contracts import Contract, EvidenceBundle, Identifier, Text

Gate = Literal["passed", "failed", "not_checked"]
PartialCause = Literal["entry_execute_inferred", "noncontiguous_allocations_omitted", "headers_inferred",
                       "instruction_cache_approximated", "erased_import_names_recovered",
                       "interactive_response_modeled", "embedded_vfs_tls_unreconstructed", "other"]


class ReconstructionGates(Contract):
    executable_bytes: Gate = "not_checked"
    entry_rva: Gate = "not_checked"
    entry_mapping: Gate = "not_checked"
    imports: Gate = "not_checked"
    iat_loader_ready: Gate = "not_checked"
    import_descriptors: Gate = "not_checked"
    machine: Gate = "not_checked"


class RunRecord(Contract):
    id: Identifier
    backend: Literal["upx_native", "unipacker", "qiling", "static", "unknown"]
    reported_outcome: Literal["extracted", "extracted_vendor_format", "partial", "failed", "timeout", "unsupported", "unknown"]
    validation: Literal["structurally_valid", "known_answer_verified", "vendor_validated", "invalid", "partial", "not_checked"]
    gates: ReconstructionGates = Field(default_factory=ReconstructionGates)
    reference: Literal["provided", "not_established"] = "not_established"
    exact_original_match: Gate = "not_checked"
    rejected_handoffs: Annotated[int, Field(ge=0, le=64)] = 0
    runtime_gaps: Annotated[list[Literal["GetDC", "CreateEventA", "other"]], Field(max_length=3)] = Field(default_factory=list)
    guest_error: Literal["corrupt_data_reported", "exit_before_handoff", "none"] = "none"
    observed_failure: Literal["unmapped_read", "unmapped_fetch", "unmapped_access", "write_protected", "read_protected", "fetch_protected", "invalid_instruction", "cpu_exception", "none"] = "none"
    partial_causes: Annotated[list[PartialCause], Field(max_length=8)] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent(self):
        if len(set(self.runtime_gaps)) != len(self.runtime_gaps):
            raise ValueError("Duplicate runtime gap")
        if len(set(self.partial_causes)) != len(self.partial_causes):
            raise ValueError("Duplicate partial cause")
        if self.partial_causes and self.reported_outcome != "partial":
            raise ValueError("Partial causes require a reported partial outcome")
        if self.reference != "provided" and (self.exact_original_match != "not_checked" or any(v != "not_checked" for v in self.gates.model_dump().values())):
            raise ValueError("Reference gates require reference evidence")
        return self


class RunEvidenceBundle(EvidenceBundle):
    schema_version: Literal["2"] = "2"
    runs: Annotated[list[RunRecord], Field(max_length=32)]

    @model_validator(mode="after")
    def unique_run_ids(self):
        ids = [o.id for o in self.observations] + [r.id for r in self.runs]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate evidence IDs")
        return self


class Diagnosis(Contract):
    category: Literal["import_reconstruction", "entry_handoff", "runtime_model_gap", "resource_budget", "decoder_input", "partial_scope", "code_comparison", "guest_fault", "unknown"]
    evidence_ids: Annotated[list[Identifier], Field(min_length=1, max_length=16)]
    explanation: Text
    limitations: Annotated[list[Text], Field(min_length=1, max_length=8)]


class DiagnosticStep(Contract):
    action: Literal["inspect_imports", "trace_handoff", "trace_decoder_input", "review_guest_api", "profile_decoder", "check_reference", "review_partial_scope", "compare_executable_bytes", "inspect_guest_fault"]
    evidence_ids: Annotated[list[Identifier], Field(min_length=1, max_length=16)]
    reason: Text


class RunAdvice(Contract):
    schema_version: Literal["2"]
    disposition: Literal["gather_evidence", "abstain"]
    diagnoses: Annotated[list[Diagnosis], Field(max_length=8)]
    steps: Annotated[list[DiagnosticStep], Field(max_length=8)]
    summary: Text

    @model_validator(mode="after")
    def steps_match_disposition(self):
        if (self.disposition == "gather_evidence") != bool(self.steps):
            raise ValueError("Gathering evidence requires diagnostic steps")
        return self


class ReportProvenance(Contract):
    collector_version: Literal["run-report-1"] = "run-report-1"
    report_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    report_bytes: Annotated[int, Field(ge=0, le=2 * 1024 * 1024)]


class RunAdviceResult(Contract):
    schema_version: Literal["2"] = "2"
    status: Literal["advice", "unavailable", "invalid_response"]
    provider: str
    model: str
    prompt_version: Literal["run-advisor-2.2"] = "run-advisor-2.2"
    evidence_sha256: str
    request_schema_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    system_prompt_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    duration_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    error_code: str | None = None
    advice: RunAdvice | None = None
    # Local provenance is added after the request, never sent to the provider.
    provenance: ReportProvenance | None = None
