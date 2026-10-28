"""AdversaryGraph-style lazy provider factory. Clients have no execution tools."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .config import AIConfig, AIError


@dataclass(frozen=True)
class ProviderReply:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None


class LLMProvider(Protocol):
    async def complete(self, system: str, user: str, schema: dict) -> ProviderReply: ...
    async def close(self) -> None: ...


class OpenAIProvider:
    def __init__(self, config: AIConfig):
        from openai import AsyncOpenAI
        self.config = config
        self.client = AsyncOpenAI(api_key=config.api_key, base_url="https://api.openai.com/v1",
                                  timeout=config.timeout_seconds, max_retries=0)

    async def complete(self, system, user, schema):
        r = await self.client.chat.completions.create(
            model=self.config.model, max_completion_tokens=self.config.max_output_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={"type": "json_schema", "json_schema": {
                "name": "unpacker_advice", "strict": True, "schema": schema}},
        )
        if not r.choices:
            raise AIError("empty_response")
        c = r.choices[0]
        if getattr(c.message, "refusal", None):
            raise AIError("provider_refusal")
        if c.finish_reason != "stop":
            raise AIError("incomplete_response")
        return ProviderReply(c.message.content or "", getattr(r.usage, "prompt_tokens", None),
                             getattr(r.usage, "completion_tokens", None))

    async def close(self):
        await self.client.close()


class ClaudeProvider:
    def __init__(self, config: AIConfig):
        from anthropic import AsyncAnthropic
        self.config = config
        self.client = AsyncAnthropic(api_key=config.api_key, base_url="https://api.anthropic.com",
                                     timeout=config.timeout_seconds, max_retries=0)

    async def complete(self, system, user, schema):
        import json
        r = await self.client.messages.create(
            model=self.config.model, max_tokens=self.config.max_output_tokens,
            system=system + "\nReturn JSON matching this schema:\n" + json.dumps(schema),
            messages=[{"role": "user", "content": user}],
        )
        if r.stop_reason != "end_turn":
            raise AIError("incomplete_response")
        text = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        return ProviderReply(text, getattr(r.usage, "input_tokens", None), getattr(r.usage, "output_tokens", None))

    async def close(self):
        await self.client.close()


class GeminiProvider:
    def __init__(self, config: AIConfig):
        from google import genai
        from google.genai import types
        self.config = config
        self.types = types
        self.client = genai.Client(api_key=config.api_key, vertexai=False,
            http_options=types.HttpOptions(base_url="https://generativelanguage.googleapis.com",
                timeout=int(config.timeout_seconds * 1000),
                retry_options=types.HttpRetryOptions(attempts=1)))

    async def complete(self, system, user, schema):
        r = await self.client.aio.models.generate_content(
            model=self.config.model, contents=user,
            config=self.types.GenerateContentConfig(system_instruction=system,
                response_mime_type="application/json", response_json_schema=schema,
                max_output_tokens=self.config.max_output_tokens),
        )
        if not r.candidates or str(r.candidates[0].finish_reason).split(".")[-1] != "STOP":
            raise AIError("incomplete_response")
        u = r.usage_metadata
        return ProviderReply(r.text or "", getattr(u, "prompt_token_count", None), getattr(u, "candidates_token_count", None))

    async def close(self):
        await self.client.aio.aclose()


def get_provider(config: AIConfig) -> LLMProvider:
    try:
        return {"openai": OpenAIProvider, "claude": ClaudeProvider, "gemini": GeminiProvider}[config.provider](config)
    except ImportError:
        raise AIError("provider_dependency_missing") from None
