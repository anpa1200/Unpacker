# Containment and reconstruction follow-up — 21 October 2026

This local, uncommitted milestone builds on the prior hardening and additional
correctness fixes. It does not establish universal unpacking accuracy.

## Implemented and verified

- High-level owned detection and artifact validation now execute in supervised child
  processes with a hard deadline. Failures become explicit inconclusive/timeout/error
  outcomes; unchecked artifacts cannot be accepted after validation worker failure.
- Direct extraction APIs account for aggregate allocated/logical output bytes and
  directory entries, including retained layers. Native/emulation workers have a
  50 ms watchdog; acceptance is checked before and after extraction. The default
  aggregate budget is 128 MiB and 4096 entries, configurable through CLI/YAML/API.
- `unpacker-sandbox` uses a capacity-limited private output tmpfs with no writable
  host-output bind during analysis. A trusted controller exports bounded uncompressed
  evidence after analysis returns. The host validates all member paths, types, sizes
  and duplicates before copying regular files with mode 0600. Invalid exports fail
  closed. A path mapping in process.json maps `/out` to the host evidence directory.
- A benign strict-quota probe filled a 1 MiB mount and received ENOSPC after exactly
  1,048,576 bytes, with zero available capacity. No sample code executed natively.
- Known-original PE validation now exposes separate executable-byte, entry-RVA,
  file-backed executable-entry, import and machine gates, with code hashes and bounded
  missing/extra import lists. Matching these static gates is not behavioral proof.
- FSG's existing fixture recovered the original code/imports/entry but left the entry
  section non-executable. The dumper now records a conservative execute-permission
  inference at the emulator handoff. The before/after static entry-mapping gate changes
  from false to true. This inferred repair keeps the overall result PARTIAL.

## Evidence

92 benign regression/unit tests pass. The final wheel builds offline; no dependency
installation or release was performed. Twenty-eight selected existing fixtures were
rerun in isolated workers: all 23 UPX fixtures retained automatic extraction, plus
ASPack, MEW, FSG, Enigma Virtual Box and gzexe. No newly acquired samples were used.
The corpus rerun preceded the final validation-failure rejection, remaining-stage
budget accounting and export-boundary adjustments; those boundaries are covered by
synthetic regressions and the production sandbox smoke checks.

Ten independent static gate runs compare before/after artifacts for five PE pairs:

| Pair | Before | After | Interpretation |
|---|---|---|---|
| ASPack | All gates pass | All gates pass | Static recovery accepted |
| Enigma Virtual Box | Imports fail | Imports fail | Partial; no false promotion |
| FSG | Entry mapping fails | All gates pass | Permission inferred; overall still partial |
| MEW | All gates pass | All gates pass | Static recovery accepted |
| UPX PE | All gates pass | All gates pass | Static recovery accepted |

The production strict sandbox also verified exact-original UPX ELF output and FSG's
passing static gates with overall PARTIAL status. Raw JSON commands, results, gate
facts, source hashes and synthetic test source are retained in the proof archive.
The archive excludes packed inputs, unpacked binaries, originals and credentials.

## Remaining limits and next work

The strict byte-capacity limit applies to the sandbox output mount. Direct API
watchdogs can overshoot between checks and are not filesystem quotas. Entry count
has watchdog/export enforcement rather than a kernel inode quota. Runtime temporary
storage and bounded host archive/report overhead are separate finite budgets.

Caller-supplied parser objects, individual low-level parsing helpers and custom
third-party plugins remain advanced in-process interfaces. Use the sandbox entry
point for an external whole-job deadline and isolation. The namespace boundary is
not a VM and does not remove kernel/emulator risk.

Standalone IAT rebuilding remains unimplemented; import-deficient Enigma output is
still partial. PE32+ integration still lacks Qiling/rootfs in this environment;
non-UPX ELF protectors, virtualization recovery, MPRESS/YZPack timeouts and other
partial reconstructions remain substantive backend work. No missing dependency was
installed or attempted in this pass.

There are 31 acquired packed/original pairs but only 12 distinct original hashes.
They already support repeatable extraction regression checks; they do not include
local build/pack recipes or broad version/compiler coverage. Controlled fixture
production requires vetted benign source, pinned build tools and appropriate packer
versions/options, with provenance/licensing review before running new packer tools.
