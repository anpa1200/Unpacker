# Unpacker: 60-second decode deadline and write-tracking repair

Date: 2026-10-22. Repository: `anpa1200/Unpacker`, local path
`/path/to/Unpacker`, branch `main`, base HEAD
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. This is a local, uncommitted repair. Existing changes and
earlier evidence were preserved. No push, publication or new third-party installation occurred.

## Delivered result

The user-approved decode default is now **60 seconds per backend** in both CLIs,
the Python API, `UnpackOptions` and `config/config.yaml`. A shared constant prevents
the previous 30-second CLI / 300-second API discrepancy. Explicit caller/configuration
overrides remain supported. The default total job deadline stays 300 seconds;
the matrix uses a stricter 75-second total budget around each 60-second attempt.
Static parser deadlines, output quotas, network isolation and reconstruction gates
were retained. The reported elapsed time also includes setup, validation and export.

The exact deployed source passes **234 benign unit tests**. An additional run that
deliberately makes YAML and Unicorn unavailable passes 15 of the new tests and
skips two optional-dependency tests. This is an import-availability simulation,
not a clean-environment CI run. An offline-built wheel and its isolated temporary
installation match all **56 deployed Python source files**. Both installed
CLIs and both installed Python entry points report the 60-second default.

The full 54-fixture matrix on this source yields **32 accepted, 6
partial and 16 unrecovered**. Status counts: `{"extracted": 29, "extracted_vendor_format": 3, "failed": 7, "partial": 6, "timeout": 5, "unsupported": 4}`.
This covers the existing acquired fixtures, not every version or configuration of
each packer. There are 31 paired cases but only 12 distinct original hashes.
Backend hints were supplied; this does not measure automatic-detection recall.

## MPRESS reproducibility

All successful rows below pass all seven known-answer PE gates: executable bytes,
entry RVA, entry mapping, imports, loader-ready IAT, complete import descriptors
and machine type. The first three runs changed only deadline defaults; later runs
also contain the write-tracking repair. Timing differences do not isolate the
effect of that repair from host scheduling and run variance.

| Run | Elapsed seconds | Result | Source cohort |
|---|---:|---|---|
| deadline60-mpress-1 | 41.89 | extracted | timeout-only candidate |
| deadline60-mpress-2 | 30.85 | extracted | timeout-only candidate |
| deadline60-mpress-3 | 34.33 | extracted | timeout-only candidate |
| deadline60-final | 28.43 | extracted | final |
| deadline60-final-repeat-2 | 32.63 | extracted | final |
| deadline60-final-repeat-3 | 33.21 | extracted | final |

The previous full-matrix 30-second MPRESS timeout and its separate 28.57-second
passing recheck remain in the earlier evidence. They were not overwritten or
reclassified. These finite repeat results do not establish a universal timing guarantee.

## NSPack recovery

The existing NSPack fixture (`case0014`) changes from the previous 30-second timeout
to `extracted` in 49.88 seconds on this build. Its
18,188 executable bytes match the known original exactly, with the same entry RVA
and all 85 imports across eight complete descriptors. All seven reconstruction
gates pass without a repair warning. A separate final-source recheck also passed all seven gates in 51.93 seconds.

The packed SHA-256 is
`527903a5e0957c4565fa1ebcd5665c6f96e3ef2f5a403ab9970d0be12bec9946`;
the original SHA-256 is
`43c5182f830865247d98f53dd488b02c3235d25d0c2179f48b3f8adcf6fa8e38`.
This establishes the recorded static reconstruction scope for this fixture,
not behavioral equivalence or coverage of every NSPack version. Both the budget
and write-tracking source changed relative to the previous matrix; causal isolation
of their effects on NSPack is not claimed.

## Concrete correctness repair

The pinned Unipacker core initialized its merged write interval from the first
unsorted range. A later write at a lower address could disappear from coverage.
For example, `[(100, 110), (20, 30)]` previously became only `[(100, 110)]`.
That can omit evidence used by write/execute and handoff decisions.

`src/unpacker/write_ranges.py` now computes a sorted, bounded union that retains
descending writes, overlaps, containment and adjacency. It preserves the pinned
engine's existing inclusive `address + size` convention; no fencepost semantics
were silently changed. PE32 addresses and a 65,536-interval fragmentation budget
are checked. Only the private worker's `unipacker.core.merge` binding is replaced;
the allocation utility and installed third-party files remain untouched.

`_unipacker_shared.py` now also catches memory-hook exceptions, records the reason
and explicitly stops the guest CPU. Old Unicorn ctypes callbacks can otherwise
swallow Python exceptions. A regression verifies the stop and preserved cause.
Coverage tests include all three reproduced descending-write failures and 500
deterministic generated writes checked against an independent set of covered bytes.

`patch-binding.json` proves the before/after behavior against the installed pinned
backend and verifies that `unipacker.utils.merge` remains unchanged. No additional
packer recovery is attributed to this bookkeeping repair without a measured transition.

## Full fixture results

Every row was run sequentially inside the existing production networkless
Bubblewrap sandbox with inputs/code read-only and bounded output export. Acquired
specimens and reconstructed executables were never launched natively. All 85
input/reference files were rehashed against the manifest and retained without
execute permission. Known originals are validation inputs, never reconstruction data.

| Case | Source family | Outcome | Validation | Elapsed seconds |
|---|---|---|---|---:|
| case0001 | ASPack | extracted | known_answer_verified | 12.65 |
| case0002 | Alienyze | failed | not_checked | 14.91 |
| case0003 | Amber | timeout | not_checked | 60.72 |
| case0004 | BeRoEXEPacker | extracted | known_answer_verified | 8.69 |
| case0005 | EXpressor | timeout | not_checked | 60.69 |
| case0006 | Enigma Virtual Box | partial | known_answer_verified | 1.54 |
| case0007 | Eronana Packer | partial | known_answer_verified | 8.21 |
| case0008 | Exe32pack | partial | known_answer_verified | 3.02 |
| case0009 | FSG | partial | known_answer_verified | 3.79 |
| case0010 | JDPack | partial | partial | 3.36 |
| case0011 | MEW | extracted | known_answer_verified | 4.28 |
| case0012 | MPRESS | extracted | known_answer_verified | 28.43 |
| case0013 | Molebox | timeout | not_checked | 60.52 |
| case0014 | NSPack | extracted | known_answer_verified | 49.88 |
| case0015 | Neolite | partial | known_answer_verified | 3.33 |
| case0016 | PECompact | failed | not_checked | 1.03 |
| case0017 | PEtite | failed | not_checked | 3.24 |
| case0018 | Packman | extracted | known_answer_verified | 6.76 |
| case0019 | RLPack | failed | not_checked | 8.95 |
| case0020 | TELock | failed | not_checked | 2.30 |
| case0021 | Themida | timeout | not_checked | 60.82 |
| case0022 | UPX | extracted | known_answer_verified | 0.93 |
| case0023 | WinUpack | unsupported | not_checked | 0.68 |
| case0024 | Yoda-Crypter | failed | not_checked | 6.82 |
| case0025 | Yoda-Protector | failed | not_checked | 1.54 |
| case0026 | ezuri | extracted | known_answer_verified | 1.64 |
| case0027 | gzexe | extracted | known_answer_verified | 1.08 |
| case0028 | midgetpack | unsupported | not_checked | 0.78 |
| case0029 | pakkero | unsupported | not_checked | 0.88 |
| case0030 | upx | extracted | known_answer_verified | 1.03 |
| case0031 | ward | extracted | known_answer_verified | 1.45 |
| case0032 | UPX | extracted | structurally_valid | 2.19 |
| case0033 | UPX | extracted | structurally_valid | 1.53 |
| case0034 | UPX | extracted | structurally_valid | 1.79 |
| case0035 | UPX | extracted | structurally_valid | 1.89 |
| case0036 | UPX | extracted | structurally_valid | 2.09 |
| case0037 | UPX | extracted | structurally_valid | 1.49 |
| case0038 | UPX | extracted | structurally_valid | 1.58 |
| case0039 | UPX | extracted | structurally_valid | 1.44 |
| case0040 | UPX | extracted_vendor_format | vendor_validated | 0.72 |
| case0041 | UPX | extracted_vendor_format | vendor_validated | 0.78 |
| case0042 | UPX | extracted | structurally_valid | 1.48 |
| case0043 | UPX | extracted | structurally_valid | 2.13 |
| case0044 | UPX | extracted | structurally_valid | 1.98 |
| case0045 | UPX | extracted | structurally_valid | 2.26 |
| case0046 | UPX | extracted_vendor_format | vendor_validated | 1.25 |
| case0047 | UPX | extracted | structurally_valid | 1.74 |
| case0048 | UPX | extracted | structurally_valid | 1.54 |
| case0049 | UPX | extracted | structurally_valid | 1.48 |
| case0050 | UPX | extracted | structurally_valid | 1.58 |
| case0051 | UPX | extracted | structurally_valid | 1.49 |
| case0052 | UPX | extracted | structurally_valid | 1.53 |
| case0053 | VMProtect | unsupported | not_checked | 1.93 |
| case0054 | YZPack | timeout | not_checked | 60.43 |

Partials remain partial even when static paired gates pass. Enigma lacks the
embedded virtual filesystem/TLS wrapper behavior; Eronana has noncontiguous live
allocations; Exe32pack uses retained input headers; FSG infers execute permission;
Neolite uses an instruction-cache approximation. JDPack retains its executable-byte
mismatch after bounded import-name recovery. These are unresolved equivalence gaps.

## Remaining failed paths

- **Alienyze (case0002)**: `failed` — Emulated CPU stopped: UcError: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED).
- **Amber (case0003)**: `timeout` — Emulation hard deadline exceeded.
- **EXpressor (case0005)**: `timeout` — Emulation hard deadline exceeded.
- **Molebox (case0013)**: `timeout` — Emulation hard deadline exceeded.
- **PECompact (case0016)**: `failed` — Unmapped emulated memory access: {'access': 19, 'address': 8396804, 'size': 2}.
- **PEtite (case0017)**: `failed` — No current-run output.
- **RLPack (case0019)**: `failed` — Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION).
- **TELock (case0020)**: `failed` — Emulated CPU stopped: UcError: Invalid instruction (UC_ERR_INSN_INVALID).
- **Themida (case0021)**: `timeout` — Emulation hard deadline exceeded.
- **WinUpack (case0023)**: `unsupported` — Nonempty input import directory is malformed; custom loader needed.
- **Yoda-Crypter (case0024)**: `failed` — Unmapped emulated memory access: {'access': 19, 'address': 8536256, 'size': 1}.
- **Yoda-Protector (case0025)**: `failed` — Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION).
- **midgetpack (case0028)**: `unsupported` — Unipacker requires a valid PE32 file.
- **pakkero (case0029)**: `unsupported` — Unipacker requires a valid PE32 file.
- **VMProtect (case0053)**: `unsupported` — Emulation callback stopped: UnsupportedAPI: RegisterWindowMessageA: API semantics are not implemented.
- **YZPack (case0054)**: `timeout` — Emulation hard deadline exceeded.

A larger deadline does not supply missing CPU/Windows semantics, a custom loader,
an ELF decoder or protected-code devirtualization. The timeout rows still require
bounded execution-path diagnosis. CPU-fault rows require a validated fault/exception
or loader model, not forced-success return values. VMProtect still needs the guest
API identified in its report and further execution validation. WinUpack needs a
loader that can handle its malformed nonempty import metadata. Midgetpack and
Pakkero need actual static recovery implementations. Optional PE32+ Qiling validation
still lacks its runtime and appropriate Windows rootfs; no such installation was
attempted. Each is a separate engineering capability and remains unsupported until tested.

## Evidence and review

The proof archive contains this report, the exact deployed source and regression
tests, deployment hashes/backups, corpus provenance/integrity records, every new
per-case JSON report and diagnostic log, package checks and SHA-256 sums. It excludes
acquired specimens, reconstructed executables, credentials and wheel binaries.
Experimental profiling/batch/block-tracing sources and their failed results are
retained under `experimental-source`; they are **not deployed**. Block tracing was
not accepted as a replacement for instruction-level handoff checks.

Historical 30-second evidence is retained separately and its previous full-matrix
summary and MPRESS recheck are included for comparison. All current matrix rows
share one exact source hash set. The immutable matrix is
`stability-evidence/final-matrix.json`; detailed per-case records include input/output
hashes, invocation budgets, acceptance gates and explicit stop reasons.
