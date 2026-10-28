"""Explicit, read-only configuration. Never source shell files or mutate os.environ."""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


class AIError(Exception):
    """Safe error code; provider exception bodies must not cross this boundary."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


_KEYS = {"openai": "OPENAI_API_KEY", "claude": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY"}
_MODELS = {"openai": "OPENAI_MODEL", "claude": "ANTHROPIC_MODEL", "gemini": "GEMINI_MODEL"}


@dataclass(frozen=True)
class AIConfig:
    provider: str
    model: str
    api_key: str = field(repr=False)
    timeout_seconds: float = 45.0
    max_output_tokens: int = 1500
    max_input_bytes: int = 32768
    max_response_bytes: int = 32768

    def __post_init__(self):
        if self.provider not in _KEYS:
            raise AIError("unsupported_provider")
        if not isinstance(self.model, str) or not self.model.strip() or len(self.model) > 200:
            raise AIError("model_required")
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise AIError("api_key_missing")
        if not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 180:
            raise AIError("invalid_timeout")
        if type(self.max_output_tokens) is not int or not 128 <= self.max_output_tokens <= 8192:
            raise AIError("invalid_output_limit")
        for n in (self.max_input_bytes, self.max_response_bytes):
            if type(n) is not int or not 1024 <= n <= 65536:
                raise AIError("invalid_byte_limit")

    @classmethod
    def load(cls, provider="openai", model=None, env_file: Path | None = None,
             environ: Mapping[str, str] | None = None, **limits):
        provider = provider.lower().strip()
        if provider not in _KEYS:
            raise AIError("unsupported_provider")
        values: dict[str, str | None] = {}
        if env_file is not None:
            try:
                from dotenv import dotenv_values
                # No shell expansion or interpolation; unrelated settings are not retained.
                parsed = dotenv_values(env_file.expanduser(), interpolate=False)
                if not env_file.expanduser().is_file():
                    raise AIError("env_file_unavailable")
                values = {k: parsed.get(k) for k in (_KEYS[provider], _MODELS[provider])}
            except ImportError:
                raise AIError("dotenv_dependency_missing") from None
            except OSError:
                raise AIError("env_file_unavailable") from None
        source = os.environ if environ is None else environ
        for key in (_KEYS[provider], _MODELS[provider]):
            if key in source:
                values[key] = source[key]
        return cls(provider=provider, model=model or values.get(_MODELS[provider]) or "",
                   api_key=values.get(_KEYS[provider]) or "", **limits)
