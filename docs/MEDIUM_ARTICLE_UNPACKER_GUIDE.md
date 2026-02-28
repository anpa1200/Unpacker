# Unpacker: A Practical Guide to Modular Malware Packer Detection and Unpacking

**Extract and validate unpacked PE/ELF samples with real examples — and prove it using String Analyzer and File Metadata tools.**

**📖 Published on Medium:** [Unpacker: A Practical Guide to Modular Malware Packer Detection and Unpacking](https://medium.com/@1200km/unpacker-a-practical-guide-to-modular-malware-packer-detection-and-unpacking-cf8ba924f25b)

---

## Table of Contents

1. [Introduction](#introduction)
2. [Git repository](#git-repository)
3. [What is Unpacker?](#what-is-unpacker)
4. [Architecture at a Glance](#architecture-at-a-glance)
5. [Detection: How the Tool Knows What’s Packed](#detection-how-the-tool-knows-whats-packed)
6. [Unpackers: One Module per Packer](#unpackers-one-module-per-packer)
   - [UPX](#upx)
   - [ASPack](#aspack)
   - [MPRESS](#mpress)
   - [Themida](#themida)
   - [VMProtect](#vmprotect)
   - [Generic](#generic)
7. [Running the Pipeline](#running-the-pipeline)
8. [Validating Unpacking: Why Proof Matters](#validating-unpacking-why-proof-matters)
9. [Validation with String Analyzer](#validation-with-string-analyzer)
10. [Validation with Basic File Information Gathering Script](#validation-with-basic-file-information-gathering-script)
11. [End-to-End Workflow](#end-to-end-workflow)
12. [Limitations and Tips](#limitations-and-tips)
13. [Summary and References](#summary-and-references)

---

## Introduction

Packed malware hides real code behind compression or encryption. To analyze behavior, extract indicators, or compare with threat intel, you first need to **unpack** the sample. Doing it by hand is tedious and error-prone; using a single rigid tool often fails when the packer isn’t the one it was built for.

**Unpacker** is a modular pipeline: it **detects** the packer (UPX, ASPack, Themida, VMProtect, etc.), **dispatches** to the right unpacker module, and **outputs** a dump you can then analyze. This guide walks through each unpacker with **real samples and proofs**, and shows how to **check and validate** correct unpacking using two companion tools you may already use:

- **[String Analyzer](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868)** — extract and categorize strings, entropy, and obfuscation hints.
- **[Basic File Information Gathering Script (fileinfo.py)](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de)** — hashes, PE/ELF metadata, packing heuristics, and deep static analysis.

Both tools are **read-only** (no execution, no decompilation), so you can safely validate unpacked files in automation or air-gapped labs.

---

## Git repository

The project is developed in the open and available on GitHub:

- **Repository:** [https://github.com/anpa1200/Unpacker](https://github.com/anpa1200/Unpacker)
- **Clone and install:**
  ```bash
  git clone https://github.com/anpa1200/Unpacker.git
  cd Unpacker
  pip install -e .
  ```
- **Run without install** (from project root):  
  `python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked`

The repo contains the full source (orchestrator, detector, unpackers), config, scripts, tests, and the in-repo version of this guide. Samples and unpacked results are not committed; use your own samples or the download script (see README) to fetch samples by packer type.

---

## What is Unpacker?

Unpacker is a **modular malware packer detection and unpacking** tool. It provides:

- **Orchestrator** — Runs: detect → select unpacker → unpack → (optional) PE rebuilder; supports **multi-layer** unpacking (e.g. VMProtect over UPX).
- **Multi-method detector** — Signatures, section names, entropy, and heuristics; outputs a **packer id** and **confidence**; supports **PE and ELF**.
- **Pluggable unpackers** — One module per packer (UPX, ASPack, MPRESS, Themida, VMProtect) plus a **generic** fallback; same interface for all.

You run one command; the tool picks the right unpacker and writes the result to an output directory. You then **validate** the result with String Analyzer and fileinfo to prove the sample is really unpacked (e.g. lower entropy, larger size, more readable APIs/strings).

---

## Architecture at a Glance

```
sample.exe
    → Detector (signatures, sections, entropy, heuristics)
    → packer_id (e.g. "aspack") + confidence
    → Dispatcher selects Unpacker (e.g. ASPackUnpacker)
    → Unpack (native UPX, or Unipacker emulation for ASPack/Themida/VMProtect)
    → output: sample.unpacked.aspack.exe
    → (optional) multi-layer: detect again and repeat
```

- **Config:** `config/config.yaml`
- **Detection:** `src/unpacker/detector/` (pipeline, sections, entropy, heuristics, signatures)
- **Unpackers:** `src/unpacker/unpackers/` (UPX, ASPack, MPRESS, Themida, VMProtect, generic)
- **CLI:** `scripts/run_unpacker.py` or `unpacker` after `pip install -e .`

---

## Detection: How the Tool Knows What’s Packed

The detector **merges** several methods and returns the best **packer_id** (and confidence) for the sample.

- **Section names** — Characteristic section names map to packers (case-insensitive), e.g.:
  - `UPX0` / `UPX1` → **upx** (0.98)
  - `.MPRESS1` / `.MPRESS2` → **mpress** (0.98)
  - `.vmp0` / `.vmp1` / `.vmp2` → **vmprotect** (0.95)
  - `ASPack`, `.aspack`, `.adata` → **aspack** (0.90)
  - `Themida` → **themida** (0.90)
- **Fallbacks** — If section names don’t match, the pipeline can use **file-content** hints (e.g. presence of "ASPack", "VMProtect", ".vmp0" in the binary) or **path hints** (e.g. path contains `vmprotect` or `themida`) so samples from known packer folders still get the right unpacker.
- **Entropy** — High section entropy suggests packed/compressed content; can yield **unknown** with a confidence score.
- **Heuristics** — Entry point in last section, few imports, etc., often reported as **unknown** when no section/signature match.

So when you run the pipeline, you’ll see output like:  
`Detected: aspack (confidence=0.9, method=sections)` or `Detected: vmprotect (confidence=0.72, method=path_hint)`.

---

## Unpackers: One Module per Packer

Each unpacker implements the same interface: it takes a sample path and options (output dir, timeout) and returns success/failure and an output path (or buffer).

### UPX

- **Method:** Prefers system **`upx -d`** (native decompression). No Python fallback in the default build.
- **Detection:** Section names `UPX0`/`UPX1`, or (for ELF) scan for `UPX0`/`UPX1` in the file if section headers are stripped.
- **Samples:** Works on PE and ELF. Place UPX-packed samples in e.g. `samples_by_packer/upx/`.
- **Output:** `sample.unpacked.upx.exe` (or `.bin` for ELF).
- **Validation:** Unpacked file is larger, entropy drops, and the detector no longer reports UPX (or reports “not packed”). Use String Analyzer to see more APIs/readable strings; use fileinfo to compare size and entropy.

### ASPack

- **Method:** **Unipacker** (emulation-based). Unipacker knows ASPack; it emulates from the entry point and dumps when the real code is unpacked. The project applies patches for safe memory read and robust dump (e.g. surviving `fix_imports` failures).
- **Detection:** Section names `ASPack`/`.aspack`/`.adata`, or file-content fallback (presence of "ASPack"/"aspack"/".aspack" in the binary).
- **Samples:** e.g. `NotePad_aspack.exe` in `samples_by_packer/aspack/`. Real proof below uses this sample.
- **Output:** `sample.unpacked.aspack.exe`.
- **Validation:** Same idea: **larger file**, **lower entropy**, **more readable strings**. We’ll show concrete String Analyzer and fileinfo output next.

### MPRESS

- **Method:** **Stub** in the open-source repo (no real unpacking yet). Detector can identify MPRESS by section names `.MPRESS1`/`.MPRESS2`.
- **Use:** Detection works; unpacking returns an error until the module is implemented.

### Themida

- **Method:** **Unipacker** in “unknown” packer mode: emulate from the entry point until section hopping or write+execute is detected, then dump. Themida is not in Unipacker’s built-in list, so it’s treated as generic/unknown.
- **Detection:** Section name "Themida", or **path hint** (path contains `themida`).
- **Samples:** e.g. in `samples_by_packer/themida/`. PE32 only (Unipacker); PE32+ fails with “Not a valid PE file”. Complex samples may **time out**; increase `--timeout` if needed.
- **Output:** `sample.unpacked.themida.exe`.
- **Validation:** Same as others: compare entropy, size, and string/API visibility with String Analyzer and fileinfo.

### VMProtect

- **Method:** Same as Themida: **Unipacker** in unknown mode (emulation then dump).
- **Detection:** Section names `.vmp0`/`.vmp1`/`.vmp2`, or file-content/VMProtect path hint.
- **Samples:** e.g. in `samples_by_packer/vmprotect/`. **PE32 only**; 64-bit (PE32+) fails with “Not a valid PE file”. On 32-bit samples the pipeline can apply multiple layers (VMProtect unpacked several times until max layers).
- **Output:** `sample.unpacked.vmprotect.exe` (and further layers if still detected as packed).
- **Validation:** Again, entropy drop, size growth, and richer strings/metadata prove successful unpacking.

### Generic

- **Method:** **Stub** — returns “Generic unpacker stub”. Used when the detector reports **unknown** (or generic) and no specific unpacker matches.
- **Use:** Placeholder for future implementation (e.g. Qiling, Speakeasy, or PE-sieve–style dumping for unknown/custom packers).

---

## Running the Pipeline

From the Unpacker project root:

```bash
# Basic run: detect + unpack, output to ./unpacked
python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked

# With timeout (useful for Themida/VMProtect)
python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked --timeout 180

# Optional: max layers, confidence threshold
python scripts/run_unpacker.py /path/to/sample.exe -o ./unpacked --max-layers 5 --confidence 0.5
```

Example output:

```
Detected: aspack (confidence=0.9, method=sections)
  Layer 1: packer=aspack -> ok
Final output: /path/to/unpacked/aspack/NotePad_aspack.unpacked.aspack.exe
```

If unpacking fails, you’ll see the error (e.g. “Not a valid PE file” for PE32+, “Unpacking timed out”, or “Generic unpacker stub”).

---

## Validating Unpacking: Why Proof Matters

Unpacking can **fail silently** (wrong OEP, truncated dump) or **succeed** but leave the file still packed (e.g. multi-layer). To **check and validate** correct unpack you need to:

1. **Confirm format** — Unpacked file is still valid PE/ELF (magic, structure).
2. **Compare size** — Unpacked is typically **larger** than packed (compression removed).
3. **Compare entropy** — Packed/compressed data has **higher entropy**; unpacked code and data usually have **lower** entropy and more structure.
4. **Re-run detection** — Unpacked file should **no longer** be detected as the same packer (or not packed at all).
5. **Inspect strings and metadata** — More readable APIs, URLs, paths, and lower “obfuscated” hint suggest real code is visible.

The two tools below give you **reproducible, static proof** without running the sample.

---

## Validation with String Analyzer

[String Analyzer](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868) extracts printable strings, classifies them (URLs, IPs, Windows APIs, DLLs, obfuscation, etc.), and computes **file entropy**. High entropy + few “useful” patterns triggers a **“likely obfuscated/packed”** note — so **before/after** unpacking you should see **entropy drop** and often **more** APIs/DLLs/readable strings.

**Install (if needed):** From `/home/andrey/git_project/String-Analyzer`:

```bash
pip install -e .
# or: python3 -m string_analyzer --help
```

**Real example — ASPack packed vs unpacked (NotePad):**

Packed (`NotePad_aspack.exe`):

```text
File Entropy: 6.25

### DLLS:
- advapi32.dll
- comdlg32.dll
- gdi32.dll
- kernel32.dll
- shell32.dll
- user32.dll

### WINDOWS API COMMANDS:
- ExitProcess
- GetProcAddress
- GetStockObject
- ShellExecuteA
- VirtualAlloc
- VirtualFree
...
```

Unpacked (`NotePad_aspack.unpacked.aspack.exe`):

```text
File Entropy: 2.38

### DLLS:
- advapi32.dll
- comdlg32.dll
- gdi32.dll
- kernel32.dll
- shell32.dll
- user32.dll

### WINDOWS API COMMANDS:
- ExitProcess
- GetProcAddress
- GetStockObject
- ShellExecuteA
- VirtualAlloc
- VirtualFree
...
```

**Proof:** **Entropy drops from 6.25 → 2.38** after unpacking. The same APIs appear because the unpacked file now exposes the real code; the packed file had high entropy from compressed/encoded data. So String Analyzer gives you a **numeric and structural** check: lower entropy and (in many cases) more or clearer categories indicate successful unpack.

Commands used:

```bash
cd /home/andrey/git_project/String-Analyzer
python3 -m string_analyzer /path/to/NotePad_aspack.exe -o packed_report.txt
python3 -m string_analyzer /path/to/NotePad_aspack.unpacked.aspack.exe -o unpacked_report.txt
```

For AI-assisted triage you can also run:

```bash
python3 -m string_analyzer /path/to/unpacked.exe --ai-prompt -o triage_prompt.md
```

---

## Validation with Basic File Information Gathering Script

The [Basic File Information Gathering Script](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de) (`fileinfo.py`) gives you **hashes, magic, file type, entropy, and PE/ELF metadata** (timestamps, entry point, sections, packing heuristic when available). No execution, no decompilation — ideal to **compare packed vs unpacked** in one table or JSON.

**Location:** `/home/andrey/git_project/Basic-File-Information-Gathering-Script/fileinfo.py`

**Real example — same ASPack pair:**

Packed:

```text
  file_name: NotePad_aspack.exe
  file_size: 33792 bytes (0.03 MB)
  entropy: 6.2524
  entropy_note: Normal
  hashes:
    md5: 85cfd7faaa37d5fd5ba48d939779c5b2
    sha256: eabfb9aaa4d1adec7c124bd0bda7a81c53249f2bac5743bedf67adf705d0d1f4
```

Unpacked:

```text
  file_name: NotePad_aspack.unpacked.aspack.exe
  file_size: 180224 bytes (0.17 MB)
  entropy: 2.3831
  entropy_note: Low
  hashes:
    md5: b17b72b437f70c29f3a4b0d49b4488d7
    sha256: f2f70b1404a19e0ad29a9b5e2deb1d0966e8a5c83546cca1aa4374720409e400
```

**Proof:** **Size 33 KB → 180 KB** (unpacked is larger); **entropy 6.25 → 2.38** (unpacked is less random). Hashes change because the file content changed. So fileinfo gives you **size, entropy, and hashes** as evidence of correct unpack.

Commands:

```bash
cd /home/andrey/git_project/Basic-File-Information-Gathering-Script
python3 fileinfo.py /path/to/NotePad_aspack.exe
python3 fileinfo.py /path/to/NotePad_aspack.unpacked.aspack.exe
```

For **maximum static metadata** (sections, imports, entropy blocks, string patterns) without decompilation:

```bash
python3 fileinfo.py --full /path/to/sample.exe
python3 fileinfo.py --full --json /path/to/sample.exe -o report.json
```

You can then diff or compare `report.json` for packed vs unpacked (e.g. section count, entropy per block, import list).

---

## End-to-End Workflow

1. **Unpack**  
   `python scripts/run_unpacker.py samples_by_packer/aspack/NotePad_aspack.exe -o unpacked/aspack`

2. **Validate with String Analyzer**  
   Compare entropy and string categories for packed vs unpacked (entropy should drop; you often get more or clearer APIs/strings).

3. **Validate with fileinfo**  
   Compare file size, entropy, and (with `--full`) sections/imports/entropy blocks. Unpacked should be larger and have lower overall entropy.

4. **Re-detect**  
   Run the Unpacker detector on the unpacked file (or use the project’s `verify_unpacking.py` script where applicable); it should no longer report the same packer (or should report “not packed”).

5. **Optional: AI triage**  
   Run String Analyzer with `--ai-prompt` on the unpacked sample and feed the prompt to your AI assistant for behavior summary.

---

## Limitations and Tips

- **PE32 vs PE32+:** Unipacker-based unpackers (ASPack, Themida, VMProtect) support **PE32 only**. For 64-bit samples you’ll see “Not a valid PE file”; you’d need a different backend or 64-bit support.
- **Timeouts:** Themida/VMProtect can be slow; use `--timeout 180` or higher.
- **Path hints:** Samples in folders (or paths) containing `vmprotect` or `themida` get a path-hint so the right unpacker is chosen even when section/signature detection doesn’t fire.
- **Multi-layer:** The pipeline can run multiple layers (e.g. VMProtect several times); check the final output and validate that one with String Analyzer and fileinfo.
- **UPX:** Install system UPX (e.g. `apt install upx-ucl`) for native decompression.
- **Unipacker:** For ASPack/Themida/VMProtect, `pip install unipacker`; on Python 3.12+ you may need `setuptools<70` for `pkg_resources`.

---

## Summary and References

- **Unpacker** detects packers (sections, entropy, heuristics, path/content hints) and runs the right unpacker (UPX native; ASPack/Themida/VMProtect via Unipacker; MPRESS/generic stubbed).
- You **validate** correct unpack by comparing **entropy**, **size**, and **strings/metadata** before and after, using **String Analyzer** and **Basic File Information Gathering Script (fileinfo.py)** — both static, no execution.
- Real proof: ASPack NotePad sample **entropy 6.25 → 2.38**, **33 KB → 180 KB**, and consistent String Analyzer/fileinfo output show the unpacked file is decompressed and structurally different from the packed one.

**References**

- **This article on Medium:** [Unpacker: A Practical Guide to Modular Malware Packer Detection and Unpacking](https://medium.com/@1200km/unpacker-a-practical-guide-to-modular-malware-packer-detection-and-unpacking-cf8ba924f25b)
- **Unpacker (source code):** [https://github.com/anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) — clone, install, and run from the repo; full README with examples and proofs is in the repository.
- String Analyzer (Medium): [A Practical Guide to String Analyzer](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868)  
- File metadata / static analysis (Medium): [One Tool to Rule Them All: File Metadata & Static Analysis for Malware Analysts and SOC Teams](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de)  
- Tools (example paths): String Analyzer and Basic File Information Gathering Script — see their repos/Medium articles for install locations; use them to validate unpacked output as shown above.

If you’re building a malware triage or unpacking pipeline, Unpacker plus these two validation tools give you a reproducible, proof-based workflow from packed sample to validated unpacked file.
