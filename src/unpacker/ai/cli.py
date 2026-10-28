"""Separate metadata-only entry point. Does not import the extraction orchestrator."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

DEFAULT_OPENAI_MODEL = "gpt-6.1-sol"


def main() -> int:
    parser = argparse.ArgumentParser(description="Unpacker AI advisor: curated metadata only; no sample execution")
    from unpacker import __version__
    parser.add_argument("--version", action="version", version="unpacker-ai "+__version__)
    parser.add_argument("evidence", type=Path, help="EvidenceBundle JSON, NOT an executable or raw run log")
    parser.add_argument("--provider", choices=("openai", "claude", "gemini"), default="openai")
    model_choice = parser.add_mutually_exclusive_group()
    model_choice.add_argument("--model", help="Explicit model (OpenAI default: gpt-6.1-sol)")
    model_choice.add_argument("--model-from-env", action="store_true", help="Use provider MODEL variable instead of the OpenAI project default")
    parser.add_argument("--env-file", type=Path, help="Explicit .env file; never sourced or modified")
    parser.add_argument("--timeout", type=float, default=45)
    delivery = parser.add_mutually_exclusive_group()
    delivery.add_argument("--preview", action="store_true", help="Print exact metadata payload offline (the default); no keys or request")
    delivery.add_argument("--send", action="store_true", help="Explicitly send the previewed metadata to the selected external provider")
    parser.add_argument("--from-report", action="store_true", help="Collect allowlisted run metadata from report.json; never sends raw report content")
    args = parser.parse_args()
    try:
        from pydantic import ValidationError
        from .advisor import advise, canonical_evidence
        from .collector import REPORT_LIMIT, collect_report, load_evidence, read_regular
        from .config import AIConfig, AIError
        from .providers import get_provider
    except ImportError:
        print("AI dependencies missing. Install 1200km-unpacker[ai] and the selected provider extra.", file=sys.stderr)
        return 2
    try:
        raw = read_regular(args.evidence, REPORT_LIMIT if args.from_report else 32768)
        provenance = None
        if args.from_report:
            evidence, provenance = collect_report(raw)
        else:
            evidence = load_evidence(raw)
        payload = canonical_evidence(evidence)
        if len(payload.encode()) > 32768:
            raise AIError("input_budget_exceeded")
        if not args.send:
            print(payload)
            return 0
        selected_model = args.model
        if selected_model is None and args.provider == "openai" and not args.model_from_env:
            selected_model = DEFAULT_OPENAI_MODEL
        config = AIConfig.load(provider=args.provider, model=selected_model, env_file=args.env_file,
                               timeout_seconds=args.timeout)

        async def run():
            provider = get_provider(config)
            try:
                return await advise(evidence, config, provider)
            finally:
                try:
                    await asyncio.wait_for(provider.close(), timeout=5)
                except Exception:
                    pass

        result = asyncio.run(run())
        if provenance is not None:
            result = result.model_copy(update={"provenance": provenance})
        print(result.model_dump_json(indent=2))
        return 0 if result.status == "advice" else 1
    except (ValidationError, ValueError, RecursionError):
        print("Invalid evidence: expected bounded EvidenceBundle JSON; raw input is not displayed.", file=sys.stderr)
    except AIError as exc:
        print(f"AI configuration/request error: {exc.code}", file=sys.stderr)
    except OSError:
        print("Evidence file unavailable.", file=sys.stderr)
    except Exception:
        print("AI provider initialization failed; details withheld to protect credentials.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
