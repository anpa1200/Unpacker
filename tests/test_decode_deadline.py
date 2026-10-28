"""One decode default for all entry points; explicit budgets remain configurable."""
import inspect
from pathlib import Path

import pytest

from unpacker.cli import build_parser as direct_parser
from unpacker.sandbox_cli import build_parser as sandbox_parser
from unpacker.orchestrator import run
from unpacker.types import DEFAULT_DECODE_TIMEOUT_SECONDS, UnpackOptions


def test_api_uses_shared_decode_default():
    assert DEFAULT_DECODE_TIMEOUT_SECONDS == 60.0
    assert UnpackOptions(Path("unused")).timeout_seconds == 60.0
    signature = inspect.signature(run)
    assert signature.parameters["timeout_seconds"].default == 60.0
    assert signature.parameters["total_timeout_seconds"].default == 300.0


def test_example_configuration_uses_shared_decode_default():
    pytest.importorskip("yaml")
    from unpacker.configuration import load_config

    example = Path(__file__).resolve().parents[1] / "config/config.yaml"
    assert load_config(example)["timeout_seconds"] == 60.0


@pytest.mark.parametrize("factory", [direct_parser, sandbox_parser])
def test_cli_default_and_explicit_override(factory):
    parser = factory()
    defaults = parser.parse_args(["unused.bin"])
    assert defaults.timeout == 60.0
    assert defaults.total_timeout == 300.0
    explicit = parser.parse_args(["unused.bin", "--timeout", "12.5"])
    assert explicit.timeout == 12.5
