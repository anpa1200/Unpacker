"""Strict, bounded contracts shared by all providers. No executable actions."""
from __future__ import annotations

from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$")]
Text = Annotated[str, Field(min_length=1, max_length=2000)]
Backend = Literal["upx_native", "unipacker", "qiling"]
Signal = Literal["upx_sections", "aspack_sections", "vmprotect_sections", "themida_sections", "high_entropy", "last_section_entry", "few_imports"]
Status = Literal["available", "missing", "failed", "timeout", "partial", "invalid", "not_checked", "structurally_valid"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class Observation(Contract):
    id: Identifier
    kind: Literal["packing_signal", "backend_status", "validation", "metric"]
    signal: Signal | None = None
    backend: Backend | None = None
    status: Status | None = None
    metric: Literal["entropy", "imports_count", "readable_page_ratio"] | None = None
    number: float | None = None

    @model_validator(mode="after")
    def coherent(self):
        present = {k for k in ("signal", "backend", "status", "metric", "number") if getattr(self, k) is not None}
        needed = {"packing_signal": {"signal"}, "backend_status": {"backend", "status"}, "validation": {"status"}, "metric": {"metric", "number"}}[self.kind]
        if present != needed:
            raise ValueError("Observation fields do not match kind")
        if self.kind == "backend_status" and self.status not in {"available", "missing", "failed", "timeout"}:
            raise ValueError("Invalid backend status")
        if self.kind == "validation" and self.status not in {"partial", "invalid", "not_checked", "structurally_valid"}:
            raise ValueError("Invalid validation status")
        if self.kind == "metric":
            if self.metric == "entropy" and not 0 <= self.number <= 8:
                raise ValueError("Entropy outside 0..8")
            if self.metric == "readable_page_ratio" and not 0 <= self.number <= 1:
                raise ValueError("Coverage outside 0..1")
            if self.metric == "imports_count" and (not 0 <= self.number <= 1_000_000 or not self.number.is_integer()):
                raise ValueError("Invalid imports count")
        return self


class EvidenceBundle(Contract):
    schema_version: Literal["1"] = "1"
    format: Literal["pe", "elf", "unknown"]
    architecture: Literal["x86", "x86_64", "arm64", "unknown"]
    parse_status: Literal["parsed", "unsupported", "error"]
    observations: Annotated[list[Observation], Field(max_length=64)]

    @model_validator(mode="after")
    def unique_ids(self):
        if len({o.id for o in self.observations}) != len(self.observations):
            raise ValueError("Duplicate evidence IDs")
        return self


class Hypothesis(Contract):
    packer_id: Literal["upx", "aspack", "vmprotect", "themida", "unknown"]
    evidence_ids: Annotated[list[Identifier], Field(min_length=1, max_length=16)]
    limitations: Annotated[list[Text], Field(max_length=8)]


class Recommendation(Contract):
    kind: Literal["review_backend", "gather_evidence", "abstain"]
    backend_id: Backend | None
    evidence_ids: Annotated[list[Identifier], Field(max_length=16)]
    reason: Text

    @model_validator(mode="after")
    def backend_only_when_reviewing(self):
        if (self.kind == "review_backend") != (self.backend_id is not None):
            raise ValueError("Backend only permitted for review_backend")
        if self.kind == "review_backend" and not self.evidence_ids:
            raise ValueError("Backend review requires evidence")
        return self


class Advice(Contract):
    schema_version: Literal["1"]
    hypotheses: Annotated[list[Hypothesis], Field(max_length=8)]
    recommendation: Recommendation
    summary: Text


class AdviceResult(Contract):
    schema_version: Literal["1"] = "1"
    status: Literal["advice", "unavailable", "invalid_response"]
    provider: str
    model: str
    prompt_version: str = "advisor-1"
    evidence_sha256: str
    duration_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    error_code: str | None = None
    advice: Advice | None = None
