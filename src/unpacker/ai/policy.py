"""Ground diagnosis locally and constrain provider schemas to reported capability.

The contextual schema is a generation aid. It never replaces the local per-citation
checks, and reports themselves remain untrusted assertions.
"""
from unpacker.ai.config import AIError
from unpacker.ai.run_contracts import RunAdvice

CATEGORY_ACTION = {"import_reconstruction": "inspect_imports", "entry_handoff": "trace_handoff",
    "runtime_model_gap": "review_guest_api", "resource_budget": "profile_decoder",
    "decoder_input": "trace_decoder_input", "partial_scope": "review_partial_scope",
    "code_comparison": "compare_executable_bytes", "guest_fault": "inspect_guest_fault"}


def actions_for_run(run):
    actions = set()
    gates = run.gates
    if "failed" in (gates.imports, gates.iat_loader_ready, gates.import_descriptors): actions.add("inspect_imports")
    if run.rejected_handoffs or "failed" in (gates.entry_rva, gates.entry_mapping): actions.add("trace_handoff")
    if run.guest_error == "corrupt_data_reported": actions.add("trace_decoder_input")
    if run.runtime_gaps: actions.add("review_guest_api")
    if run.reported_outcome == "timeout": actions.add("profile_decoder")
    if run.reference == "not_established": actions.add("check_reference")
    if run.reported_outcome == "partial": actions.add("review_partial_scope")
    if gates.executable_bytes == "failed": actions.add("compare_executable_bytes")
    if run.observed_failure != "none": actions.add("inspect_guest_fault")
    return actions


def diagnostic_routes(evidence):
    return {run.id: sorted(actions_for_run(run)) for run in evidence.runs}


def check_run_advice(advice, evidence):
    routes = diagnostic_routes(evidence)
    ids = set(routes) | {o.id for o in evidence.observations}
    for item in [*advice.diagnoses, *advice.steps]:
        if any(ref not in ids for ref in item.evidence_ids):
            raise AIError("unknown_evidence_reference")
        action = item.action if hasattr(item, "action") else CATEGORY_ACTION.get(item.category)
        if action and not any(action in routes.get(ref, ()) for ref in item.evidence_ids):
            raise AIError("unsupported_diagnostic_action")


def contextual_schema(evidence):
    schema = RunAdvice.model_json_schema()
    routes = diagnostic_routes(evidence)
    allowed = {action for actions in routes.values() for action in actions}
    ids = sorted(set(routes) | {o.id for o in evidence.observations})
    defs = schema["$defs"]
    if allowed:
        defs["DiagnosticStep"]["properties"]["action"]["enum"] = sorted(allowed)
    else:
        # Keep the item definition valid even when no item is allowed.
        schema["properties"]["steps"]["maxItems"] = 0
        schema["properties"]["disposition"]["enum"] = ["abstain"]
    defs["Diagnosis"]["properties"]["category"]["enum"] = sorted(
        {"unknown"} | {category for category, action in CATEGORY_ACTION.items() if action in allowed})
    for name in ("Diagnosis", "DiagnosticStep"):
        if ids:
            defs[name]["properties"]["evidence_ids"]["items"]["enum"] = ids
    if not ids:
        schema["properties"]["diagnoses"]["maxItems"] = 0
    return schema
