# Unpacker

Packer detection and unpacking workflow for malware analysts: detect UPX, ASPack, Themida, VMProtect, and related packing patterns so static analysis can reach real code and strings.

## CTI Use

Use this before strings, imports, YARA review, or deeper reverse engineering when a sample appears packed. The output supports malware-family triage, detection engineering, and analyst notes, but it must be validated before claims are made.

## Defender Outputs

| Output | Use |
|---|---|
| Packer detection | Triage and analyst routing |
| Unpacked sample | Follow-on static analysis |
| Entropy/validation notes | Confidence review |
| Multi-layer workflow | Packed malware handling |
| Integration path | Feed String Analyzer, PE Import Analyzer, AIDebug |

**Modular malware packer detection and unpacking (UPX, ASPack, Themida, VMProtect). PE and ELF. One command: detect → unpack → validate.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://github.com/anpa1200/Unpacker/actions/workflows/tests.yml/badge.svg)](https://github.com/anpa1200/Unpacker/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/badge/GitHub-anpa1200%2FUnpacker-green.svg)](https://github.com/anpa1200/Unpacker)

---

## What it does

Packed malware hides real code behind compression or encryption. Unpacker:

1. **Detects** the packer using section names, entropy, heuristics, and optional path/content hints (PE and ELF).
2. **Dispatches** to the matching unpacker (UPX native; ASPack/Themida/VMProtect via [Unipacker](https://github.com/unipacker/unipacker) for 32-bit, or [Qiling](https://github.com/qilingframework/qiling) for 64-bit VMProtect).
3. **Outputs** an unpacked file you can analyze or validate with tools like [String Analyzer](https://github.com/anpa1200/String-Analyzer) and [Basic File Information Gathering Script](https://github.com/anpa1200/Basic-File-Information-Gathering-Script).

One command, one pipeline; supports **multi-layer** unpacking (e.g. several VMProtect layers).

---

## Features

| Feature | Description |
|--------|-------------|
| **Multi-method detection** | Section names (UPX0/UPX1, .aspack, .vmp0, Themida, …), entropy, heuristics; PE + ELF. |
| **Pluggable unpackers** | UPX (native), ASPack/Themida/VMProtect (Unipacker for PE32; Qiling for PE32+ VMProtect), MPRESS/generic (stub). |
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

**Requirements:** Python 3.10+, optional system UPX and Unipacker for full unpacker coverage.

```bash
cd Unpacker
pip install -e .
# Or: pip install -r requirements.txt
```

- **UPX (for UPX unpacking):** install system UPX, e.g. `apt install upx-ucl` or [upx.github.io](https://upx.github.io/).
- **ASPack / Themida / VMProtect (32-bit):** `pip install unipacker`. On Python 3.12+ you may need `pip install 'setuptools<70'` for `pkg_resources`.
- **VMProtect (64-bit):** `pip install qiling` and set **QILING_ROOTFS** to a directory containing a Windows x64 rootfs (e.g. `x8664_windows` with DLLs). See [Qiling rootfs](https://github.com/qilingframework/rootfs). Optional: `pip install -e ".[emulation]"` to pull in Qiling.

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

## Unpacking techniques (how this tool works)

The tool uses different **unpacking techniques** depending on the packer and binary format.

### Detection (before unpacking)

- **Section names** — Known section name patterns map to packers (e.g. `UPX0`/`UPX1` → UPX, `.aspack`/`.adata` → ASPack, `.vmp0`/`.vmp1` → VMProtect, `Themida` → Themida). Case-insensitive.
- **File content fallback** — If sections don’t match, the file is scanned for packer-related strings (e.g. `ASPack`, `VMProtect`, `.vmp0`) to still assign a packer.
- **Path hint** — If the sample path contains `vmprotect` or `themida`, that packer is preferred so samples in known folders get the right unpacker.
- **Entropy** — High section entropy suggests packed/compressed data; can yield a generic “packed” or “unknown” result.
- **Heuristics** — Entry point in last section, few imports, etc., often reported as “unknown.”

Detection supports **PE and ELF**; the best matching packer (by confidence) is chosen and the corresponding unpacker is run.

### Unpacking by technique

| Technique | Used for | How it works |
|-----------|----------|--------------|
| **Native decompression** | **UPX** (PE & ELF) | Calls system `upx -d`. The packer format is known; UPX decodes in place and writes the decompressed image. No emulation. |
| **Emulation + dump (Unipacker)** | **ASPack, Themida, VMProtect** (PE32 only) | Loads the PE in [Unicorn](https://www.unicorn-engine.org/) via [Unipacker](https://github.com/unipacker/unipacker). Emulates from the **entry point**; the engine runs until it detects an “unpacking done” condition (e.g. section hop, write+execute region, or packer-specific logic). Then it **dumps** the process memory (image base + size) to a new PE file. Unipacker knows ASPack; for Themida/VMProtect it uses a **generic “unknown”** strategy (emulate until heuristic trigger, then dump). The tool applies **patches** to Unipacker: safe page-by-page memory read (avoids crashes on unmapped regions) and robust dump (if import fix fails, zero IAT and still write the dump). |
| **Emulation + dump (Qiling)** | **VMProtect** (PE32+ / 64-bit only) | Used when the sample is 64-bit (Unipacker is 32-bit only). Loads the PE in [Qiling](https://github.com/qilingframework/qiling) with a Windows **rootfs** (emulated DLLs). Runs emulation with a **timeout**. After run (or timeout), reads the **loaded image** from emulated memory (base + `SizeOfImage`) and writes it to disk. No packer-specific logic—generic “run then dump” so heavy protectors may only partially unpack. |
| **Stub** | **MPRESS, generic** | Detection may identify the packer, but the unpacker module is not implemented; the pipeline returns an error or “generic unpacker stub.” |

#### 1. Native decompression (UPX)

The packer format is public and reversible. UPX stores compressed data (e.g. NRV2B or LZMA) in known sections (`UPX0`, `UPX1`); the decompressor algorithm is fixed. The tool invokes system **`upx -d`**: UPX reads the file, decompresses, and writes a new PE/ELF with the original code and layout restored. No execution of the packed binary; works for PE and ELF.

#### 2. Emulation + dump — Unipacker (ASPack, Themida, VMProtect, PE32 only)

Many packers place a **stub** at the entry point that allocates memory, decompresses/decrypts the real code into it, then jumps to it (the **original entry point**, OEP). We **run** that stub in a CPU emulator until the real code is in memory, then **dump** that memory to a file.

- **Emulation:** [Unipacker](https://github.com/unipacker/unipacker) loads the PE in [Unicorn](https://www.unicorn-engine.org/). Execution starts at the PE entry point (the packer stub). Windows APIs (e.g. `VirtualAlloc`, `VirtualProtect`) are stubbed so the stub can allocate and run. When the stub decompresses and jumps to the unpacked code, we detect that and dump.
- **When to dump:** (1) **Section hop** — execution jumps to a different section that was written at runtime. (2) **Write+execute (W+X)** — a region written during emulation is made executable and execution enters it. (3) **Packer-specific** — for ASPack, Unipacker has built-in logic; for Themida/VMProtect it uses the generic heuristics.
- **Dump:** Read emulated memory from image base for SizeOfImage (or allocated range), build a PE, fix the import table (IAT). **Patches in this repo:** (1) **Safe read** — read page-by-page and fill unmapped pages with zeros so the dump completes. (2) **Robust dump** — if IAT fix throws, zero the import directory and still write the dump.
- **Why 32-bit only:** Unipacker’s loader is for PE32; for PE32+ (64-bit) it fails, so we use Qiling for 64-bit VMProtect.

#### 3. Emulation + dump — Qiling (VMProtect 64-bit only)

[Qiling](https://github.com/qilingframework/qiling) is a full system emulator: it loads the PE and a Windows **rootfs** (DLLs). We run **`ql.run(timeout=...)`** with no packer-specific “unpack done” heuristic—we rely on **time**. After run or timeout, we read memory from the image base for SizeOfImage and write it to disk. The result is a raw memory snapshot (IAT not fixed in this path). Heavy protectors may only partially unpack within the timeout.

#### 4. Stub (MPRESS, generic)

No unpacker implemented; the pipeline returns a clear error.

### Summary

- **UPX:** Direct decompression; fast and deterministic.
- **ASPack / Themida / VMProtect (32-bit):** Emulation in Unicorn via Unipacker; dump on section hop / W+X or packer logic; patches for safe read and robust dump.
- **VMProtect (64-bit):** Emulation in Qiling with rootfs; timed run then dump; no IAT fix.
- **Multi-layer:** Re-detect and repeat up to `max_layers` (default 5).

### Is it safe to run real (packed) code in the emulator?

**Short answer:** The packed code runs **inside the emulator**, not natively on your CPU, so it is much safer than executing the sample on the host—but you should still run the tool in an isolated environment (e.g. a VM or a dedicated analysis machine).

**Why emulation is relatively safe:**

- **Unipacker (Unicorn):** The sample’s instructions are **interpreted** by the emulator. They do not run on the host processor. When the code “calls” Windows APIs (e.g. `VirtualAlloc`, `CreateFileA`), Unipacker’s **stubs** run instead of the real OS: they typically only update the emulator’s internal state (e.g. allocate emulated memory, return a fake handle). So the packed code cannot directly access your real filesystem, network, or hardware unless a stub explicitly forwards to the host—and in Unipacker’s design, stubs are meant to simulate behavior, not to perform real dangerous operations.
- **Qiling:** Same idea (emulated CPU + emulated APIs), but Qiling is a full system emulator and can be configured to map host paths into the emulated environment. If you map a host directory into the rootfs or the emulated “C:\”, writes could affect the host. **Best practice:** use a self-contained rootfs (e.g. only DLLs and a minimal layout) and do not map sensitive host directories. Run in a VM so that even a misconfiguration has limited impact.

**Recommendations:**

- Treat all samples as hostile. Run the unpacker in a **VM**, **sandbox**, or **dedicated analysis machine**, not on a production or personal system.
- Do not rely on emulation as a perfect sandbox: stub bugs or design choices could, in theory, expose the host. Isolation (VM + no sensitive mounts for Qiling) keeps risk low.
- **UPX** does not run the sample at all; it only decompresses. So UPX unpacking is safe from a “running code” perspective (apart from trusting the `upx` binary and the decompressed output).

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
| ASPack, Themida, VMProtect (Unipacker / Qiling) | Done (PE32 via Unipacker; PE32+ VMProtect via Qiling when rootfs set) |
| MPRESS, generic unpacker | Stub (detection only / error) |
| PE rebuilder (IAT) | Stub |
| Signature DB | Empty (optional) |

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Related repositories & articles

| Resource | Link |
|----------|------|
| **Unpacker (this repo)** | [GitHub](https://github.com/anpa1200/Unpacker) · [Medium: Unpacker Guide](https://medium.com/@1200km/unpacker-a-practical-guide-to-modular-malware-packer-detection-and-unpacking-cf8ba924f25b) |
| **Static-malware-Analysis-Orchestrator** | [GitHub](https://github.com/anpa1200/Static-malware-Analysis-Orchestrator) — runs triage, strings, PE imports, and Unpacker in one pipeline · [Medium: Full workflow](https://medium.com/@1200km/basic-static-malware-analysis-from-triage-to-unpacking-explained-and-automated-9442ef3b11b8) |
| **PE-Import-Analyzer** | [GitHub](https://github.com/anpa1200/PE-Import-Analyzer) · [Medium: PE Import Analyzer Guide](https://medium.com/@1200km/pe-import-analyzer-a-practical-guide-for-malware-analysts-and-reverse-engineers-29b8b98aeaf3) |
| **String-Analyzer** | [GitHub](https://github.com/anpa1200/String-Analyzer-) · [Medium: String Analyzer Guide](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868) |
| **Basic-File-Information-Gathering-Script** | [GitHub](https://github.com/anpa1200/Basic-File-Information-Gathering-Script) · [Medium: File Metadata & Static Analysis](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de) |
| **PROJECT_SCENARIO.md** | Research, design, and links to PackHero, PISEP, Qiling, CAPE, PE-sieve, packing-box, etc. |
| **Author** | [Medium @1200km](https://medium.com/@1200km) |
