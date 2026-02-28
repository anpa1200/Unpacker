# Unpacker — Malware Packer Detection & Unpacking Tool

## 1. Research Summary

### 1.1 Packer Detection (How to Identify Packers)

| Method | Description | References |
|--------|-------------|------------|
| **Signature-based** | Byte patterns (EP, sections, code) in a database (PEiD-style). 5500+ signatures in packing-box/peid. | PEiD, packing-box |
| **Section names** | Distinct names: UPX → `UPX0`/`UPX1`, MPRESS → `.MPRESS1`/`.MPRESS2`, VMProtect → `.vmp0`/`.vmp1`/`.vmp2`. | Manual unpacking guides |
| **Entropy** | Packed code has high entropy (7–8); plaintext low. Single/multi-layer detection with high accuracy. | MDPI entropy analysis, PISEP |
| **Heuristics** | Minimal/corrupt IAT, unusual entry point, executable sections that shouldn’t be, EP in last section. | RE best practices |
| **ML / graph-based** | PackHero (graph + Call Graph Matching), section–entropy plots (PISEP). Better on VM-based packers. | PackHero, PISEP, MDPI |

**Conclusion:** Detector should combine **signatures + section names + entropy + heuristics**. ML can be an optional later phase.

### 1.2 Unpacking Techniques

| Approach | Description | Use case |
|----------|-------------|----------|
| **Packer-specific** | Dedicated algo per packer (e.g. UPX -d, ASPack-specific OEP tricks). | Known packers with reversible/unpack APIs |
| **Generic dynamic** | Run in sandbox/emulator, detect OEP (EIP transition, WxorX, execution histogram), dump memory, reconstruct PE/IAT. | Unknown/custom packers |
| **Emulation** | Qiling, Speakeasy: no real execution; API/syscall hooks; dump from emulator memory. | Safe, scriptable unpacking |
| **DBI** | Pin/PinDemonium: instrument execution, detect when code is written then executed (WxorX), dump at OEP. | Generic unpacking with OEP detection |
| **Debugger + hooks** | CAPE-style: debugger + API hooks (e.g. Detours), YARA-driven breakpoints, capture payloads. | Full sandbox + unpacking |

**OEP detection:** Critical to dump *at* OEP. Methods: execution histogram (spike then flat), entropy + API scan, WxorX transition (write then execute).

**Post-dump:** Reconstruct IAT (PE-sieve `/imp`: unerase / rebuild R0–R2), fix PE headers, optional use of PE-sieve as external tool.

### 1.3 Architecture References

- **Qiling:** Emulation core (Unicorn) + loaders (PE/ELF) + OS layer + event-driven hooks (API, syscall, address).
- **CAPE:** Modular (Processing, Auxiliary, Signatures, Machinery); debugger + API hooks; YARA-driven unpacking.
- **PinDemonium:** DBI with WxorX handler, hooking, dumping, IAT reconstruction modules.
- **PE-sieve:** Scan process memory, dump PE, IAT reconstruction modes (none / unerase / rebuild R0–R2).

---

## 2. Project Goals

- **Modular, not monolithic:** orchestrator + detector + pluggable unpacker modules.
- **Robust:** multiple detection methods; per-packer and generic unpacking; optional multi-layer (re-detect and re-unpack).
- **Extensible:** add new packer types by adding a detector rule and an unpacker module.
- **Clear contracts:** shared interfaces for “detection result” and “unpack result” so any module can be swapped or extended.

---

## 3. High-Level Architecture

```
                    +------------------+
                    |   Orchestrator   |
                    | (CLI / API)      |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v
+----------------+  +----------------+  +----------------+
| Packer         |  | Unpacker       |  | PE Rebuilder   |
| Detector       |  | Dispatcher     |  | (IAT, headers) |
| (multi-method) |  | (per-pack)     |  | (optional)     |
+--------+-------+  +--------+-------+  +----------------+
         |                   |
         |         +---------+---------+
         |         |                   |
         v         v                   v
+----------------+  +----------------+  +----------------+
| Signatures     |  | UPX module     |  | Generic        |
| Sections       |  | ASPack module  |  | (emulation/    |
| Entropy        |  | MPRESS module  |  |  DBI/dump)     |
| Heuristics     |  | ...            |  |                |
+----------------+  +----------------+  +----------------+
```

- **Orchestrator:** Load sample → run **Packer Detector** → get packer id(s) / “unknown” → **Unpacker Dispatcher** selects module(s) → run unpacking → optionally **PE Rebuilder** → output unpacked file(s) and metadata. Can loop for multi-layer.
- **Packer Detector:** Implements several methods (signatures, section names, entropy, heuristics); merges results into a single “detection result” (packer name/id, confidence, method).
- **Unpacker modules:** One (or more) module per packer type; each implements the same interface. A **generic** module handles “unknown” or when no specific module exists (emulation or external PE-sieve/TinyTracer style).
- **PE Rebuilder:** Optional step to fix IAT and PE headers (conceptually aligned with PE-sieve `/imp`); can call external tool or implement own logic.

---

## 4. Component Specifications

### 4.1 Orchestrator

- **Input:** Path to sample (PE), options (max layers, timeout, output dir, which unpacker to prefer).
- **Flow:**
  1. Run detector on current sample.
  2. If not packed (or confidence below threshold), stop and return “no unpacking needed” or “unpacked”.
  3. Select unpacker module(s) by packer id; if none, use generic module.
  4. Run selected module; get unpacked buffer/path.
  5. Optionally run PE rebuilder on unpacked output.
  6. If multi-layer: set current sample = unpacked output, go to 1; else finish.
- **Output:** Unpacked file(s), report (detection result, which module ran, hashes, errors).

### 4.2 Packer Detector

- **Input:** Sample path or buffer, optional PE parsed struct.
- **Output:** `DetectionResult`: list of `(packer_id, confidence, method)` (e.g. `upx`, 0.95, `signature`).
- **Methods (modules):**
  - **Signatures:** Pattern database (EP, section data); match against known packer signatures.
  - **Sections:** Map section names to packer (UPX0/UPX1 → UPX, etc.).
  - **Entropy:** Per-section entropy; high entropy + executable → packed; optional multi-layer hint.
  - **Heuristics:** Suspicious EP (e.g. in last section), tiny/corrupt IAT, mismatch between sections and EP.
- **Config:** Enable/disable methods, confidence threshold, signature DB path.

### 4.3 Unpacker Module Interface

Every unpacker module (UPX, ASPack, generic, …) implements:

- **`can_handle(packer_id: str, sample_path: Path) -> bool`**  
  Whether this module can unpack this packer / this file.
- **`unpack(sample_path: Path, options: UnpackOptions) -> UnpackResult`**  
  Returns: success, output path or buffer, logs, error if failed.

**UnpackResult:** `success: bool`, `output_path: Optional[Path]`, `output_buffer: Optional[bytes]`, `log: List[str]`, `error: Optional[str]`, `metadata: dict`.

**UnpackOptions:** `output_dir`, `timeout`, `rebuild_iat: bool`, `max_memory_mb`, etc.

### 4.4 Unpacker Modules (Per Packer Type)

- **UPX:** Prefer native `upx -d` if available; else Python decompression (UPX algorithm) or subprocess. No execution needed.
- **ASPack:** Known OEP tricks or emulation/DBI; optional integration with existing scripts/tools.
- **MPRESS:** Similar: specific decompression or generic path.
- **Themida / VMProtect:** No simple unpack; use **generic** module (emulation or DBI + OEP detection + dump).
- **Generic:** Run in emulator (e.g. Qiling/Speakeasy) or via external (PE-sieve + TinyTracer, or CAPE). Detect OEP → dump → optional IAT rebuild. Handles “unknown” and heavy protectors.

New packers = new module implementing the same interface + optional new detector rules/signatures.

### 4.5 PE Rebuilder (Optional)

- **Input:** Dumped PE (file or buffer).
- **Tasks:** Rebuild or unerase IAT (PE-sieve-like modes), fix entry point, section headers if needed.
- **Implementation:** Can wrap PE-sieve CLI or implement minimal IAT discovery + PE write.

---

## 5. Directory Layout (Modular)

```
Unpacker/
├── README.md
├── PROJECT_SCENARIO.md          # this file
├── pyproject.toml / setup.py    # package deps
├── requirements.txt
│
├── src/
│   └── unpacker/
│       ├── __init__.py
│       ├── orchestrator.py     # main pipeline
│       ├── types.py            # DetectionResult, UnpackResult, UnpackOptions
│       │
│       ├── detector/           # Packer detector
│       │   ├── __init__.py
│       │   ├── base.py         # interface
│       │   ├── pipeline.py     # runs all methods, merges results
│       │   ├── signatures.py   # signature-based
│       │   ├── sections.py    # section-name rules
│       │   ├── entropy.py     # entropy-based
│       │   └── heuristics.py  # IAT/EP heuristics
│       │
│       ├── unpackers/          # Unpacker modules
│       │   ├── __init__.py     # registry, dispatch
│       │   ├── base.py         # BaseUnpacker interface
│       │   ├── upx.py
│       │   ├── aspack.py
│       │   ├── mpress.py
│       │   └── generic.py      # emulation / DBI / external
│       │
│       └── pe_rebuilder/       # optional
│           ├── __init__.py
│           └── iat.py          # IAT fix / PE-sieve wrapper
│
├── data/                       # detector data
│   └── signatures/             # signature DB (later)
│
├── config/
│   └── config.yaml             # detector/unpacker options
│
├── tests/
│   ├── test_detector.py
│   ├── test_unpackers.py
│   └── samples/                # encrypted / non-malicious test samples
│
└── scripts/                    # CLI entrypoint
    └── run_unpacker.py
```

---

## 6. Technology Choices

- **Language:** Python 3.10+ (PE parsing, plugins, fast iteration). Performance-critical paths (e.g. signature scan) can be Cython or ctypes later.
- **PE parsing:** `pefile` or `pypdf`-style library for safe parsing (avoid crashes on malformed PE).
- **Signature DB:** Start with JSON/YAML list of (name, pattern, offset); later align with PEiD-style DB if needed.
- **Generic unpacking:** Prefer **emulation** (Qiling or Speakeasy) in process, or **subprocess** to PE-sieve/TinyTracer for safety and fewer deps. DBI (Pin) can be optional external.
- **Config:** YAML for detector/unpacker options; env or CLI overrides.

---

## 7. Implementation Phases

| Phase | Deliverables |
|-------|--------------|
| **1 – Core** | `types.py`, detector pipeline (stub methods), one unpacker (e.g. UPX), orchestrator that: detect → dispatch → unpack → save. CLI script. |
| **2 – Detector** | Implement signatures (with small DB), section names, entropy, heuristics; merge and confidence; unit tests. |
| **3 – Unpackers** | ASPack, MPRESS modules (or stubs); generic module (emulation or external PE-sieve); registry and dispatch by packer_id. |
| **4 – Rebuilder** | Optional PE rebuilder (IAT unerase/rebuild), integrate into orchestrator. |
| **5 – Hardening** | Timeouts, size limits, sandbox (optional), logging, reporting; multi-layer loop. |
| **6 – Optional** | ML-based detector plugin, more packer modules, PEiD signature import. |

---

## 8. References

- PackHero: Scalable Graph-based Packer Identification (arXiv).
- PISEP: Section-entropy plot packer identification (Springer).
- Pinicorn: Automated Dynamic Analysis for Unpacking 32-Bit PE Malware (MDPI).
- Qiling Framework Architecture (GitHub Wiki).
- CAPE Sandbox (What is CAPE, Processing/Modular design).
- PE-sieve: Import table reconstruction (hasherezade).
- Packing-box / PEiD (signatures, Docker).
- “Manually Unpacking Malware” (section names, entropy, IAT).
- PinDemonium: DBI-based generic unpacker (Black Hat).

---

*This scenario is the single source of truth for the Unpacker project: modular orchestrator, multi-method detector, and pluggable unpacker modules per packer type.*
