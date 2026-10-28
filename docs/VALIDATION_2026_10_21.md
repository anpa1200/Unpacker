# Unpacker hardening and measured coverage

21 October 2026. Candidate version 1.1.0; changes remain local and uncommitted.

## Measured improvement

| Check | Before | Hardened result |
|---|---:|---:|
| Automatic UPX routing/extraction on acquired UPX fixtures | 5/23 | 23/23 |
| Static gzip-wrapper extraction | Unsupported | 1/1, exact original SHA-256 |
| Regression/unit tests | 47 | 74 passing |
| Original-code recovery evidence in the acquired paired cases | UPX and supplemental ASPack | Seven distinct cases have exact file or meaningful executable-byte matches |

The seven paired cases are ASPack, Enigma Virtual Box, FSG, MEW, UPX PE, UPX ELF,
and gzexe. Code-byte identity alone does not establish intact imports, valid section
permissions or runnable behavior: Enigma Virtual Box and FSG remain partial. The
full-file original matches are the ELF UPX and gzexe cases. No recovery is certified
solely from lower entropy, larger size or output existence.

Automatic outcomes across the composite 54-case rerun: `{'extracted_unverified': 5, 'unsupported': 4, 'no_packing_evidence': 4, 'partial': 13, 'timeout': 2, 'failed': 2, 'extracted': 21, 'extracted_vendor_format': 3}`.
Source-label-guided outcomes: `{'completed': 31, 'unsupported': 6, 'partial': 13, 'timeout': 2, 'failed': 2}`. Completed extraction and
structural validity are distinguished from known-original proof and complete recovery.

## Changes implemented

- Bounded integrity-verified UPX detection, including stripped ELF and vendor formats.
- Removed path labels and downgraded incidental content strings; retained corroborating
  evidence and parser/method failures. Explicit import parsing and corrected one-section heuristic.
- Fresh per-attempt directories, ownership/regular-file checks, empty/oversized/unchanged
  output rejection, hashes, structural validation and optional known-original comparison.
- Supervised child processes, hard deadlines, descendant cleanup, environment clearing,
  bounded logs, output and memory limits; Unipacker post-dump pause now stops batch execution.
- Explicit partial Qiling snapshots, no zero-only success, rootfs selection, controlled
  initialization failures and observable degraded imports/missing reads.
- Layer provenance and terminal reasons, no filename feedback loops, no blind re-emulation
  of a dump, no success on zero layers or unsupported/plain inputs.
- Opt-in generic/MPRESS PE32 emulation and bounded static gzip-wrapper extraction.
- A fail-closed Linux Bubblewrap entry point for isolated parsing and extraction.
- Real bounded JSON signature loading, explicit checked YAML configuration, safer bounded
  archive acquisition and hash verification, package 1.1.0 and gated artifact publishing.

## Evidence method and scope

The original 54 downloaded fixtures and 31 source-paired originals were reused; no new
sample acquisition or native sample execution occurred. The full hardened run used 30-second
backend budgets, compared with eight seconds in the original primary survey. Therefore
emulation improvement is a combination of code, routing and increased budget; no unbiased
whole-corpus speedup claim is made. Native UPX budgets were not a limiting factor.

The full run completed 108 processes. Subsequent targeted reruns exercised the changed
23 UPX paths (46 processes), then three DOS/COFF/TOS terminal-status paths (six processes).
The composite matrix selects the latest relevant record per case and names its evidence
root. Earlier records remain preserved. The original-source comparison independently
recomputed 86 artifact hashes and original executable bytes inside a read-only sandbox.

Targeted corrections were necessary because decompressed UPX utility binaries can still
contain marker strings, and DOS MZ/COFF outputs must not be misparsed as PE. Explicit UPX
NotPacked diagnostics now suppress those residual section hints, while vendor-native
non-PE artifacts stop with a distinct non-parser-validated status.

The production sandbox entry point was separately smoke-tested with the ELF UPX fixture
and its original: `known_answer_verified`, exact original SHA-256. The wheel built locally
and entry-point smoke checks succeeded outside the checkout. Final source includes a
subsequent logging-only change preserving capped diagnostics on worker timeout; synthetic
tests cover that boundary. Source snapshots and hashes identify each tested revision.

## Remaining limitations

**This is not close to 100% across all packers.** MPRESS and YZPack fixtures still time out
at 30 seconds; PECompact and PEtite yield no accepted output; several other PE packers yield
partial dumps; some files lack import data required by the current Unipacker loader. The
four acquired ELF protectors ezuri, midgetpack, pakkero and ward still lack supported
extraction backends. Four automatic cases have no packing evidence and are not proof of
unpacked input. VMProtect produces structurally valid dumps without a paired-original
completeness proof. Qiling/PE32+ protector extraction remains untested without the optional
runtime and rootfs. Standalone IAT rebuilding remains explicitly unsupported.

The sandbox is a Linux namespace boundary, not a VM or a guarantee against kernel or
emulator defects. Output has per-file limits, not an aggregate filesystem quota. Only
the sandbox entry point has an external hard deadline across all parsing stages; direct
static parsing remains in-process. Signature loading works, but no comprehensive bundled
signature collection or calibrated detector benchmark is supplied. One sample per most
families cannot establish packer/version-wide accuracy. AI advice does not repair these
backend capabilities and is not a completion validator.

## Per-case results

| Case | Family | Detected before → after | Automatic outcome | Label-guided outcome | Original proof |
|---|---|---|---|---|---|
| case0001 | ASPack | aspack → aspack | extracted_unverified | completed | executable bytes match |
| case0002 | Alienyze | unknown → unknown | unsupported | unsupported | not established |
| case0003 | Amber | none → none | no_packing_evidence | completed | not established |
| case0004 | BeRoEXEPacker | unknown → unknown | partial | partial | not established |
| case0005 | EXpressor | none → none | no_packing_evidence | completed | not established |
| case0006 | Enigma Virtual Box | enigma → enigma | partial | partial | executable bytes match |
| case0007 | Eronana Packer | unknown → unknown | partial | partial | not established |
| case0008 | Exe32pack | unknown → unknown | extracted_unverified | completed | not established |
| case0009 | FSG | unknown → unknown | partial | partial | executable bytes match |
| case0010 | JDPack | unknown → unknown | partial | partial | not established |
| case0011 | MEW | unknown → mew | extracted_unverified | completed | executable bytes match |
| case0012 | MPRESS | mpress → mpress | timeout | timeout | not established |
| case0013 | Molebox | unknown → unknown | extracted_unverified | completed | not established |
| case0014 | NSPack | unknown → unknown | partial | partial | not established |
| case0015 | Neolite | unknown → unknown | partial | partial | not established |
| case0016 | PECompact | unknown → unknown | failed | failed | not established |
| case0017 | PEtite | unknown → petite | failed | failed | not established |
| case0018 | Packman | unknown → unknown | partial | partial | not established |
| case0019 | RLPack | unknown → unknown | partial | partial | not established |
| case0020 | TELock | unknown → unknown | partial | partial | not established |
| case0021 | Themida | themida → themida | partial | partial | not established |
| case0022 | UPX | upx → upx | extracted | completed | executable bytes match |
| case0023 | WinUpack | unknown → unknown | unsupported | unsupported | not established |
| case0024 | Yoda-Crypter | unknown → unknown | partial | partial | not established |
| case0025 | Yoda-Protector | unknown → unknown | partial | partial | not established |
| case0026 | ezuri | none → none | no_packing_evidence | unsupported | not established |
| case0027 | gzexe | none → gzexe | extracted | completed | exact file |
| case0028 | midgetpack | unknown → unknown | unsupported | unsupported | not established |
| case0029 | pakkero | unknown → unknown | unsupported | unsupported | not established |
| case0030 | upx | unknown → upx | extracted | completed | exact file |
| case0031 | ward | none → none | no_packing_evidence | unsupported | not established |
| case0032 | UPX | unknown → upx | extracted | completed | not established |
| case0033 | UPX | unknown → upx | extracted | completed | not established |
| case0034 | UPX | upx → upx | extracted | completed | not established |
| case0035 | UPX | unknown → upx | extracted | completed | not established |
| case0036 | UPX | upx → upx | extracted | completed | not established |
| case0037 | UPX | unknown → upx | extracted | completed | not established |
| case0038 | UPX | unknown → upx | extracted | completed | not established |
| case0039 | UPX | unknown → upx | extracted | completed | not established |
| case0040 | UPX | none → upx | extracted_vendor_format | completed | not established |
| case0041 | UPX | none → upx | extracted_vendor_format | completed | not established |
| case0042 | UPX | unknown → upx | extracted | completed | not established |
| case0043 | UPX | unknown → upx | extracted | completed | not established |
| case0044 | UPX | upx → upx | extracted | completed | not established |
| case0045 | UPX | upx → upx | extracted | completed | not established |
| case0046 | UPX | none → upx | extracted_vendor_format | completed | not established |
| case0047 | UPX | unknown → upx | extracted | completed | not established |
| case0048 | UPX | unknown → upx | extracted | completed | not established |
| case0049 | UPX | unknown → upx | extracted | completed | not established |
| case0050 | UPX | unknown → upx | extracted | completed | not established |
| case0051 | UPX | unknown → upx | extracted | completed | not established |
| case0052 | UPX | unknown → upx | extracted | completed | not established |
| case0053 | VMProtect | vmprotect → vmprotect | extracted_unverified | completed | not established |
| case0054 | YZPack | unknown → unknown | timeout | timeout | not established |

## Review and reproduce

The archive contains source snapshots, manifests, per-run reports/commands, independent
comparisons and a SHA-256 inventory. Binaries, samples and paired originals are excluded
from the archive and remain in the original local corpus. Public acquisition URLs and
hashes are retained for deliberate reacquisition. No keys or private .env contents are
included. No commits, pushes, deployments or package publication were performed.
