"""Offline model selection: project default without editing shared credentials."""
import json
import sys

import pytest

pytest.importorskip("pydantic", minversion="2.7")
from unpacker.ai import cli
from unpacker.ai.providers import ProviderReply


class Provider:
    async def complete(self,*args):
        return ProviderReply(json.dumps(dict(schema_version="2",disposition="abstain",diagnoses=[],steps=[],summary="No unsupported recovery claim.")))
    async def close(self):pass


@pytest.mark.parametrize("provider,options,expected", [
    ("openai", [], "gpt-6.1-sol"),
    ("openai", ["--model","explicit-model"], "explicit-model"),
    ("openai", ["--model-from-env"], "old-shared-model"),
    ("claude", [], "configured-claude-model"),
    ("gemini", [], "configured-gemini-model"),
])
def test_model_selection_and_shared_file_preservation(provider,options,expected,tmp_path,monkeypatch,capsys):
    import unpacker.ai.providers
    report=tmp_path/"evidence.json"
    report.write_text(json.dumps(dict(schema_version="2",format="pe",architecture="x86",parse_status="parsed",observations=[],runs=[])))
    env=tmp_path/"shared.env"
    env.write_text("OPENAI_API_KEY=fixture-key\nOPENAI_MODEL=old-shared-model\nANTHROPIC_API_KEY=fixture-key\nANTHROPIC_MODEL=configured-claude-model\nGEMINI_API_KEY=fixture-key\nGEMINI_MODEL=configured-gemini-model\n")
    before=env.read_bytes()
    for name in ("OPENAI_API_KEY","OPENAI_MODEL","ANTHROPIC_API_KEY","ANTHROPIC_MODEL","GEMINI_API_KEY","GEMINI_MODEL"):
        monkeypatch.delenv(name,raising=False)
    selected=[]
    def factory(config):
        selected.append(config.model)
        return Provider()
    monkeypatch.setattr(unpacker.ai.providers,"get_provider",factory)
    monkeypatch.setattr(sys,"argv",["unpacker-ai",str(report),"--provider",provider,"--env-file",str(env),*options])
    assert cli.main()==0
    assert selected==[expected]
    assert json.loads(capsys.readouterr().out)["model"]==expected
    assert env.read_bytes()==before


def test_environment_model_opt_in_and_explicit_model_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(sys,"argv",["unpacker-ai","unused.json","--model","explicit","--model-from-env"])
    with pytest.raises(SystemExit) as exc:cli.main()
    assert exc.value.code==2
