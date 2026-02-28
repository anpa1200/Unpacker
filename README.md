# Unpacker

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![GitHub](https://img.shields.io/badge/GitHub-anpa1200%2FUnpacker-green.svg)](https://github.com/anpa1200/Unpacker)

**Modular malware packer detection and unpacking:** detect the packer (UPX, ASPack, Themida, VMProtect, …), run the right unpacker, and validate the result with entropy and static analysis.

---

## What it does

Packed malware hides real code behind compression or encryption. Unpacker:

1. **Detects** the packer using section names, entropy, heuristics, and optional path/content hints (PE and ELF).
2. **Dispatches** to the matching unpacker (UPX native; ASPack/Themida/VMProtect via [Unipacker](https://github.com/unipacker/unipacker) emulation).
3. **Outputs** an unpacked file you can analyze or validate with tools like [String Analyzer](https://github.com/anpa1200/String-Analyzer) and [Basic File Information Gathering Script](https://github.com/anpa1200/Basic-File-Information-Gathering-Script).

One command, one pipeline; supports **multi-layer** unpacking (e.g. several VMProtect layers).

---

## Features

| Feature | Description |
|--------|-------------|
| **Multi-method detection** | Section names (UPX0/UPX1, .aspack, .vmp0, Themida, …), entropy, heuristics; PE + ELF. |
| **Pluggable unpackers** | UPX (native `upx -d`), ASPack, Themida, VMProtect (Unipacker emulation), MPRESS/generic (stub). |
| **Path/content hints** | Samples in `.../vmprotect/` or `.../themida/` get the right unpacker even without section match. |
| **Multi-layer** | Re-detect and unpack up to N layers (configurable). |
| **Validation-friendly** | Output is static dumps; prove unpack with entropy/size/strings (see [Real-life example](#real-life-example-with-proof) below). |

---

## Repository

- **GitHub:** [https://github.com/anpa1200/Unpacker](https://github.com/anpa1200/Unpacker)
- **Clone:**
  ```bash
  git clone https://github.com/anpa1200/Unpacker.git
  cd Unpacker
  ```

---

## Install

**Requirements:** Python 3.8+, optional system UPX and Unipacker for full unpacker coverage.

```bash
cd Unpacker
pip install -e .
# Or: pip install -r requirements.txt
```

- **UPX (for UPX unpacking):** install system UPX, e.g. `apt install upx-ucl` or [upx.github.io](https://upx.github.io/).
- **ASPack / Themida / VMProtect:** `pip install unipacker`. On Python 3.12+ you may need `pip install 'setuptools<70'` for `pkg_resources`.

---

## Usage

```bash
# Unpack one sample (output under ./unpacked by default)
python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked

# With timeout (recommended for Themida/VMProtect)
python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked --timeout 180

# After pip install -e . you can use:
unpacker /path/to/sample.exe -o ./unpacked
```

**Options:** `--max-layers`, `--confidence`, `--timeout`.

**Example output:**

```
Detected: aspack (confidence=0.9, method=sections)
  Layer 1: packer=aspack -> ok
Final output: /path/to/unpacked/aspack/NotePad_aspack.unpacked.aspack.exe
```

---

## Real-life example with proof

Using an **ASPack-packed** sample (`NotePad_aspack.exe`), we show that unpacking is correct by comparing **entropy** and **file size** before and after.

### 1. Run the unpacker

```bash
python scripts/run_unpacker.py samples_by_packer/aspack/NotePad_aspack.exe -o unpacked/aspack
```

Result: `unpacked/aspack/NotePad_aspack.unpacked.aspack.exe`.

### 2. Proof: entropy and size

| Metric | Packed (`NotePad_aspack.exe`) | Unpacked (`NotePad_aspack.unpacked.aspack.exe`) |
|--------|-------------------------------|-------------------------------------------------|
| **File size** | 33,792 bytes (33 KB) | 180,224 bytes (176 KB) |
| **Entropy** | 6.25 | 2.38 |

Unpacked file is **larger** (compression removed) and has **lower entropy** (real code/data instead of compressed blob). That is the expected signature of successful unpacking.

### 3. How to reproduce the proof

**String Analyzer** (categorized strings + entropy):

```bash
# From String Analyzer project
string-analyzer /path/to/NotePad_aspack.exe -o packed_report.txt
string-analyzer /path/to/NotePad_aspack.unpacked.aspack.exe -o unpacked_report.txt
```

Compare reports: packed shows **File Entropy: 6.25**, unpacked **File Entropy: 2.38**.

**Basic File Information Gathering Script** (hashes, size, entropy):

```bash
# From Basic-File-Information-Gathering-Script project
python3 fileinfo.py /path/to/NotePad_aspack.exe
python3 fileinfo.py /path/to/NotePad_aspack.unpacked.aspack.exe
```

You get `file_size` and `entropy` for both; unpacked has higher size and lower entropy. With `--full` or `--json` you can compare sections, imports, and entropy blocks.

These tools are **read-only** (no execution); see the [Article](#article--validation-guide) for full validation workflow and links to their Medium guides.

---

## Project layout

```
Unpacker/
├── README.md                 # This file
├── PROJECT_SCENARIO.md       # Research and design
├── pyproject.toml
├── requirements.txt
├── config/config.yaml       # Detector and orchestrator settings
├── data/signatures/         # Optional signature DB (empty by default)
├── docs/
│   └── MEDIUM_ARTICLE_UNPACKER_GUIDE.md   # Full guide (Medium-style)
├── scripts/
│   ├── run_unpacker.py      # Main CLI
│   ├── step0_find_and_download_samples.py # Malware Bazaar download by packer
│   └── verify_unpacking.py  # Check unpacked format/size/detection
├── src/unpacker/
│   ├── orchestrator.py      # detect → unpack → optional rebuild
│   ├── detector/            # Signatures, sections, entropy, heuristics
│   ├── unpackers/           # UPX, ASPack, Themida, VMProtect, MPRESS, generic
│   └── pe_rebuilder/        # Optional IAT fix (stub)
└── tests/
```

Samples and unpacked output (`samples_by_packer/`, `unpacked/`) are **not** in the repo; use your own or the download script (see below).

---

## Getting samples

Use the provided script to fetch samples by packer tag from [Malware Bazaar](https://bazaar.abuse.ch/) (requires API key):

```bash
export MALWARE_BAZAAR_API_KEY='your-key'
python scripts/step0_find_and_download_samples.py
```

Samples are saved under `samples_by_packer/<packer>/` and named like `{name}_{packer}.exe` or `{hash}_{packer}.bin`.

---

## Validation and verification

- **Manual:** Compare packed vs unpacked with [String Analyzer](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868) (entropy, string categories) and [Basic File Information Gathering Script](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de) (size, entropy, PE metadata).
- **In-repo:** For UPX outputs, `python scripts/verify_unpacking.py` checks format, size growth, and that the unpacked file is no longer detected as packed.

---

## Article & validation guide

**📖 [Unpacker: A Practical Guide to Modular Malware Packer Detection and Unpacking](https://medium.com/@1200km/unpacker-a-practical-guide-to-modular-malware-packer-detection-and-unpacking-cf8ba924f25b)** — Published on Medium.

The same content is in the repo as **[docs/MEDIUM_ARTICLE_UNPACKER_GUIDE.md](docs/MEDIUM_ARTICLE_UNPACKER_GUIDE.md)** (Markdown). The article covers:

- Git repository and clone/install from GitHub
- Each unpacker (UPX, ASPack, MPRESS, Themida, VMProtect, generic) with real usage
- Validation with String Analyzer and fileinfo, with **real output** (entropy 6.25 → 2.38, 33 KB → 180 KB)
- End-to-end workflow and limitations

---

## Status

| Component | Status |
|-----------|--------|
| Orchestrator, detector (sections, entropy, heuristics), dispatcher | Done |
| UPX (native) | Done |
| ASPack, Themida, VMProtect (Unipacker) | Done (PE32; may time out on heavy samples) |
| MPRESS, generic unpacker | Stub (detection only / error) |
| PE rebuilder (IAT) | Stub |
| Signature DB | Empty (optional) |

---

## References

- **Unpacker repo:** [https://github.com/anpa1200/Unpacker](https://github.com/anpa1200/Unpacker)
- **Unpacker article (Medium):** [Unpacker: A Practical Guide to Modular Malware Packer Detection and Unpacking](https://medium.com/@1200km/unpacker-a-practical-guide-to-modular-malware-packer-detection-and-unpacking-cf8ba924f25b)
- **PROJECT_SCENARIO.md** — Research, design, and links to PackHero, PISEP, Qiling, CAPE, PE-sieve, packing-box, etc.
- **String Analyzer:** [Medium guide](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868) · [GitHub](https://github.com/anpa1200/String-Analyzer)
- **Basic File Information Gathering Script:** [Medium guide](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de) · [GitHub](https://github.com/anpa1200/Basic-File-Information-Gathering-Script)
