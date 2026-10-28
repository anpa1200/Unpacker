"""Contextual output constraints supplement per-citation validation."""
import json
import pytest

pytest.importorskip("pydantic", minversion="2.7")
from unpacker.ai.config import AIError
from unpacker.ai.policy import actions_for_run, check_run_advice, contextual_schema, diagnostic_routes
from unpacker.ai.run_contracts import RunAdvice, RunEvidenceBundle


def bundle(runs):
    return RunEvidenceBundle.model_validate(dict(format="pe",architecture="x86",parse_status="parsed",observations=[],runs=runs))


def run(**changes):
    data=dict(id="layer.1",backend="unipacker",reported_outcome="failed",validation="not_checked",guest_error="corrupt_data_reported")
    data.update(changes)
    return data


def test_provider_schema_only_allows_supported_diagnostic_types_and_known_ids():
    evidence=bundle([run()])
    schema=contextual_schema(evidence)
    assert schema["$defs"]["DiagnosticStep"]["properties"]["action"]["enum"] == ["check_reference","trace_decoder_input"]
    assert schema["$defs"]["Diagnosis"]["properties"]["category"]["enum"] == ["decoder_input","unknown"]
    assert schema["$defs"]["DiagnosticStep"]["properties"]["evidence_ids"]["items"]["enum"] == ["layer.1"]
    assert diagnostic_routes(evidence)=={"layer.1":["check_reference","trace_decoder_input"]}


def test_cross_run_reference_is_checked_even_when_global_schema_allows_action():
    evidence=bundle([run(guest_error="none",reported_outcome="timeout"),run(id="layer.2",guest_error="none",runtime_gaps=["GetDC"])])
    advice=RunAdvice.model_validate(dict(schema_version="2",disposition="gather_evidence",diagnoses=[],steps=[
        dict(action="review_guest_api",evidence_ids=["layer.1"],reason="Unrelated citation.")],summary="Synthetic test."))
    assert "review_guest_api" in contextual_schema(evidence)["$defs"]["DiagnosticStep"]["properties"]["action"]["enum"]
    with pytest.raises(AIError,match="unsupported_diagnostic_action"):check_run_advice(advice,evidence)


def test_no_unsupported_step_is_generated_when_no_diagnostic_route_exists():
    evidence=bundle([run(guest_error="none",reference="provided",reported_outcome="extracted")])
    schema=contextual_schema(evidence)
    assert not actions_for_run(evidence.runs[0])
    assert schema["properties"]["steps"]["maxItems"] == 0
    assert schema["properties"]["disposition"]["enum"] == ["abstain"]


def test_empty_evidence_cannot_create_citations():
    schema=contextual_schema(bundle([]))
    assert schema["properties"]["diagnoses"]["maxItems"] == 0
    assert schema["properties"]["steps"]["maxItems"] == 0


def test_context_constraints_do_not_leak_between_requests():
    first=contextual_schema(bundle([run()]))
    context=contextual_schema(bundle([run(guest_error="none",reported_outcome="timeout")]))
    assert context["$defs"]["DiagnosticStep"]["properties"]["action"]["enum"] == ["check_reference","profile_decoder"]
    assert "profile_decoder" not in json.dumps(first)
