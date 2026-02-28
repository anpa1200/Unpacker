# Unpacker

Modular **malware packer detection and unpacking** tool: orchestrator, multi-method detector, and pluggable unpacker modules per packer type.

## Architecture

- **Orchestrator** — Runs the pipeline: detect → select unpacker → unpack → (optional) PE rebuilder; supports multi-layer unpacking.
- **Packer detector** — Multi-method: signatures, section names, entropy, heuristics; outputs packer id and confidence.
- **Unpacker modules** — One module per packer (UPX, ASPack, MPRESS, …) plus a **generic** module for unknown/heavy protectors. Same interface for all.

See **[PROJECT_SCENARIO.md](PROJECT_SCENARIO.md)** for research summary, design, and implementation phases.

## Layout

```
Unpacker/
├── PROJECT_SCENARIO.md    # Full scenario and references
├── README.md
├── pyproject.toml
├── requirements.txt
├── config/config.yaml
├── data/signatures/       # (optional) signature DB
├── src/unpacker/
│   ├── types.py           # DetectionResult, UnpackResult, UnpackOptions
│   ├── orchestrator.py    # Main pipeline
│   ├── detector/          # Signatures, sections, entropy, heuristics, pipeline
│   ├── unpackers/         # UPX, ASPack, MPRESS, generic + registry
│   └── pe_rebuilder/      # Optional IAT/PE fix
├── scripts/run_unpacker.py
└── tests/
```

## Install

```bash
cd /home/andrey/git_project/Unpacker
pip install -e .
# Or: pip install -r requirements.txt
```

For UPX unpacking, install UPX on your system (e.g. `apt install upx-ucl` or download from https://upx.github.io/).

## Usage

```bash
# From project root (src on PYTHONPATH via scripts)
python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked

# Or after pip install -e .
unpacker /path/to/sample.exe -o ./unpacked
```

Options: `--max-layers`, `--confidence`, `--timeout`.

## Status

- **Done:** Orchestrator, detector pipeline (signatures stub, sections, entropy, heuristics), unpacker interface and registry, UPX (native), stubs for ASPack, MPRESS, generic.
- **TODO:** Signature DB, implement ASPack/MPRESS/generic unpackers (emulation or PE-sieve), PE rebuilder (IAT), multi-layer tests.

## Article

**[Unpacker: A Practical Guide](docs/MEDIUM_ARTICLE_UNPACKER_GUIDE.md)** — Medium-style article with real examples, each unpacker explained, and validation using [String Analyzer](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868) and [Basic File Information Gathering Script](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de). Copy the markdown to Medium or use as a reference.

## References

See PROJECT_SCENARIO.md for links to PackHero, PISEP, Qiling, CAPE, PE-sieve, packing-box/PEiD, and related work.
