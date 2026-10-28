"""Provider wire contracts with fake SDK responses. No live API requests."""
import asyncio
from types import SimpleNamespace as N
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("pydantic", minversion="2.7")
from unpacker.ai.config import AIConfig, AIError
from unpacker.ai.contracts import Advice
from unpacker.ai.providers import OpenAIProvider, ClaudeProvider, GeminiProvider, get_provider


def test_openai_schema_usage_refusal_and_truncation():
    p = OpenAIProvider.__new__(OpenAIProvider)
    p.config = AIConfig("openai", "fixture-model", "fixture-key")
    create = AsyncMock(return_value=N(choices=[N(finish_reason="stop", message=N(content="{}", refusal=None))], usage=N(prompt_tokens=10, completion_tokens=2)))
    p.client = N(chat=N(completions=N(create=create)), close=AsyncMock())
    reply = asyncio.run(p.complete("system", "metadata", Advice.model_json_schema()))
    assert reply.text == "{}" and reply.input_tokens == 10 and reply.output_tokens == 2
    args = create.call_args.kwargs
    assert args["response_format"]["json_schema"]["strict"] is True
    assert "tools" not in args
    assert args["max_completion_tokens"] == 1500
    create.return_value.choices[0].message.refusal = "fixture refusal"
    with pytest.raises(AIError, match="provider_refusal"):
        asyncio.run(p.complete("s", "u", {}))
    create.return_value.choices[0].message.refusal = None
    create.return_value.choices[0].finish_reason = "length"
    with pytest.raises(AIError, match="incomplete_response"):
        asyncio.run(p.complete("s", "u", {}))
    asyncio.run(p.close())
    p.client.close.assert_awaited_once()


def test_claude_schema_text_and_truncation():
    p = ClaudeProvider.__new__(ClaudeProvider)
    p.config = AIConfig("claude", "fixture-model", "fixture-key")
    create = AsyncMock(return_value=N(stop_reason="end_turn", content=[N(type="text", text="{}")], usage=N(input_tokens=5, output_tokens=2)))
    p.client = N(messages=N(create=create), close=AsyncMock())
    r = asyncio.run(p.complete("system", "metadata", Advice.model_json_schema()))
    assert r.text == "{}" and r.input_tokens == 5
    assert "unpacker" not in create.call_args.kwargs.get("tools", [])
    assert '"additionalProperties": false' in create.call_args.kwargs["system"]
    create.return_value.stop_reason = "max_tokens"
    with pytest.raises(AIError, match="incomplete_response"):
        asyncio.run(p.complete("s", "u", {}))


def test_gemini_schema_usage_and_truncation():
    p = GeminiProvider.__new__(GeminiProvider)
    p.config = AIConfig("gemini", "fixture-model", "fixture-key")
    p.types = N(GenerateContentConfig=lambda **kwargs: kwargs)
    generate = AsyncMock(return_value=N(candidates=[N(finish_reason="STOP")], text="{}", usage_metadata=N(prompt_token_count=4, candidates_token_count=2)))
    p.client = N(aio=N(models=N(generate_content=generate), aclose=AsyncMock()))
    r = asyncio.run(p.complete("s", "u", Advice.model_json_schema()))
    assert r.input_tokens == 4
    assert generate.call_args.kwargs["config"]["response_mime_type"] == "application/json"
    generate.return_value.candidates[0].finish_reason = "MAX_TOKENS"
    with pytest.raises(AIError, match="incomplete_response"):
        asyncio.run(p.complete("s", "u", {}))


@pytest.mark.parametrize("provider,sdk", [("openai", "openai"), ("claude", "anthropic"), ("gemini", "google.genai")])
def test_installed_sdk_constructor_contracts_without_network(provider, sdk):
    pytest.importorskip(sdk)
    async def construct_and_close():
        p = get_provider(AIConfig(provider, "fixture-model", "fixture-key"))
        await p.close()
    asyncio.run(construct_and_close())
