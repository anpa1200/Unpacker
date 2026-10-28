"""Benign parsed header objects; no binary parsing or specimen execution."""
from types import SimpleNamespace
import pytest
from unpacker.detector.format_ import parsed_architecture


@pytest.mark.parametrize("machine,magic,expected", [(0x14c,0x10b,"x86"), (0x8664,0x20b,"x86_64"),
    (0xaa64,0x20b,"arm64"), (0x14c,0x20b,"unknown"), (0x8664,0x10b,"unknown"), (0xffff,0x20b,"unknown")])
def test_pe_header_consistency(machine, magic, expected):
    pe = SimpleNamespace(FILE_HEADER=SimpleNamespace(Machine=machine), OPTIONAL_HEADER=SimpleNamespace(Magic=magic))
    assert parsed_architecture(pe=pe) == expected


@pytest.mark.parametrize("machine,bits,expected", [("EM_386",32,"x86"), ("EM_X86_64",64,"x86_64"),
    ("EM_AARCH64",64,"arm64"), ("EM_X86_64",32,"unknown"), ("EM_ARM",32,"unknown")])
def test_elf_header_consistency(machine, bits, expected):
    assert parsed_architecture(elf=SimpleNamespace(header={"e_machine":machine},elfclass=bits)) == expected


def test_absent_headers():
    assert parsed_architecture() == "unknown"
    assert parsed_architecture(pe=object()) == "unknown"
