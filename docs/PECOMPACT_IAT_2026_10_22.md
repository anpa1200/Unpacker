# Unpacker: PECompact IAT reconstruction repair

Date: 2026-10-22. Repository: `anpa1200/Unpacker`, local branch `main`, base HEAD
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. Changes are local and uncommitted.

## Verified outcome

**The existing PECompact fixture now passes all seven unchanged acceptance gates.**
The final sequential run completed in 10.28 seconds under the retained 60-second
decode deadline and 75-second total job budget. The earlier focused known-answer
run completed in 8.52 seconds; the reference-free run in 8.88 seconds.

All three produced the same 155,648-byte output, SHA-256:

`f071dc68cfec3da5b6a3798d2653b6a80f2b319cd70934783f9b530411982923`

The reference-free invocation did not mount the paired original. It correctly
reports `extracted_unverified` / `structurally_valid`; the known-answer runs report
`extracted` / `known_answer_verified`. Reconstruction never reads reference bytes.

The focused candidate suite passes **288 benign tests**, including 15 new
descriptor-reconstruction tests. The final 12-fixture cohort has eight accepted,
one partial and three unrecovered fixtures. All seven previously accepted fixtures
retain every acceptance gate. This is **one newly accepted corpus fixture**, not
universal PECompact support or a new complete-corpus benchmark.

The prior full 54-case benchmark remains a historical result from the earlier
234-test build: 32 accepted / 6 partial / 16 unrecovered. It was not rerun here.

## Diagnosis grounded in the recorded mismatches

The previous reconstruction failed at two required IAT zero terminators:

| RVA | Actual bytes | Expected | Source of the selected sequence |
| --- | --- | --- | --- |
| `0x25d60` | `6d1e0010` | `00000000` | bootstrap `kernel32` observations |
| `0x25cb1` | `75736572` | `00000000` | bootstrap `user32` observations |

The installed upstream rebuilder finds the first byte occurrence of observed
function addresses and patches only the counted symbol entries. It neither
requires an aligned, declared IAT nor writes its required zero terminator. Here,
the bootstrap sequences lie outside the declared image sections; the `user32`
sequence starts at unaligned RVA `0x25ca9`. Promoting those sequences creates
invalid extra descriptors. Simply zeroing adjacent bytes would overwrite
unrelated payload and would not establish that they were import arrays.

The captured live image retains the actual descriptor table at RVA `0x6760`.
It identifies eight original application modules and their IAT RVAs. Each lookup
array and IAT contains resolved addresses, so the earlier name-based retained-table
parser cannot parse its lookup entries as hint/name RVAs. There are also two
copies of every complete application binding sequence: for example KERNEL32 at
`0x6008` and `0x681c`. The retained descriptor selects `FirstThunk=0x6008`;
duplicate byte patterns therefore need not be guessed away. Static indirect-call
references corroborate that array; they are diagnostic evidence, not a selection
heuristic used by the repair.

`iat-evidence/diagnosis.json` preserves all bounded candidate locations,
terminator bytes, declared-directory evidence and the upstream source hash.

## Implemented reconstruction

`src/unpacker/pe_rebuilder/bound_imports.py` recovers the table rooted in the
**live header's declared import directory**. The shared backend invokes this path
only for PECompact after ordinary retained-name recovery fails.

1. Validate nonoverlapping image-section ranges, aligned descriptors and arrays,
   zero-terminated descriptors/thunks, valid module names and supported descriptor
   state. Timestamped or forwarded binding metadata is rejected by this profile.
2. Require the retained lookup and IAT values to agree. Map each address to exactly
   one symbol or ordinal observed for the same explicitly named module. Ambiguous
   identities, missing observations and omitted bindings for represented modules
   are rejected. Neither a reference file nor a byte-search ordering supplies names.
3. Build new zero-terminated descriptors, lookup arrays and hint/name metadata in
   a zeroed workspace beyond all declared sections. Preserve the descriptor-selected
   IAT locations, patch their loader-ready values, and preserve their zero terminators.
4. Plan and validate the entire operation before mutating the detached image.
   The live emulator and original input are unchanged by reconstruction.

The recovered table has **eight descriptors / 85 symbols**, versus the old
invalid ten-descriptor / 92-observation reconstruction. The `kernel32` and `user32`
bootstrap observation groups are explicitly recorded as unrepresented by the
retained descriptor table. They are not silently claimed as application imports.

Limits remain 32 MiB per image, 128 descriptors, 4,096 observed symbols, 64 KiB of
new metadata and the existing worker deadlines/output quotas. No host DLL loading,
native specimen execution, network access or new external dependencies were added.
Invalid or unsupported retained layouts preserve the existing reconstruction
fallback and rejection behavior; acceptance gates were not relaxed.

## Acceptance evidence

The final PECompact comparison establishes:

- Executable bytes: **18,188 compared, zero differences**, SHA-256
  `87df1115898e921af61f034e10b5600c34509aae9ac5ca4dc30e364cf5e457b8`.
- Entry point: RVA `0x532c`, mapped to file-backed executable data.
- Imports: all **85 match**, with no missing or unexpected imports.
- Loader-ready IAT: all 85 bindings and eight terminators pass.
- Descriptor consistency and target machine: pass.

These are the existing code/import/entry static comparison gates. They do not
establish native execution equivalence, resource fidelity, relocation correctness
or universal recovery. `complete_recovery` remains `not_established` in metadata.

The accepted handoff precedes `CreateEventA`. Its missing guest semantics were
not a dependency of this repair, so no dummy API success or new event model was
introduced. Other fixtures can still legitimately require that unsupported API.

## Final scoped regression cohort

| Case | Family | Result | Seconds | Acceptance |
| --- | --- | --- | ---: | --- |
| case0016 | PECompact | extracted | 10.28 | 7/7 |
| case0001 | ASPack | extracted | 14.02 | 7/7 |
| case0004 | BeRoEXEPacker | extracted | 5.54 | 7/7 |
| case0011 | MEW | extracted | 3.86 | 7/7 |
| case0012 | MPRESS | extracted | 35.30 | 7/7 |
| case0014 | NSPack | extracted | 50.43 | 7/7 |
| case0018 | Packman | extracted | 7.36 | 7/7 |
| case0022 | UPX | extracted | 0.89 | 7/7 |
| case0010 | JDPack | partial | 3.39 | 6/7; executable bytes differ |
| case0002 | Alienyze | failed | 17.13 | No accepted output |
| case0017 | PEtite | failed | 3.40 | No accepted output |
| case0053 | VMProtect | unsupported | 2.66 | No accepted output |

JDPack remains partial because executable bytes differ. Alienyze still stops at
an unmapped instruction fetch. PEtite still exits after its `Corrupt Data!` path;
the decoder-input diagnosis remains unresolved. VMProtect still stops at
unsupported `GetDC`. None of those statuses was promoted by this pass.

## Tests, packaging and reproducibility

The 15 new benign-memory tests exercise duplicate resolved arrays, named/ordinal
recovery, absent OriginalFirstThunk, a zero terminator, detached writes, ambiguous
names, missing or omitted observations, conflicting arrays, invalid alignment,
timestamped metadata, malformed names, overlapping ranges, absent workspace,
invalid directory bounds, observation quotas and truncated reads.

The first full candidate test attempt had one staging-only failure because the
existing archive-validation test's reviewed acquisition-script file had not been
copied into the stage. Its log is preserved. Copying that unchanged dependency
resolved the failure; the test exercises benign ZIP bytes and makes no requests.

The initial diagnostic was also blocked before emulation because the outer
sandbox disallowed namespace creation. The approved retry ran the same production
networkless Bubblewrap isolation. Both records are preserved. No specimen was
run outside that isolation.

The owned wheel was built offline with existing tooling and installed without
dependencies into a fresh `/tmp` directory. All **59 package source files** match
the final regression hashes in both wheel and installed tree. Isolated CLI help
checks pass and retain the 60-second default. This is an offline package smoke
check, not publication or a third-party dependency installation.

The proof archive contains source/test snapshots, baseline and deployment hashes,
run commands, per-case reports, diagnostic JSON, successful/failed test logs and
packaging checks, with a SHA-256 manifest. It excludes specimens, recovered
executables, live-image binary captures, wheels and credentials. Binary captures
remain local solely as diagnostic evidence. No commit, push or publication occurred.

## Remaining boundary

This path requires a retained, declared PE32 import table and unambiguous observed
bindings. Erased descriptors, conflicting lookup/IAT contents, timestamped binding
metadata, unresolved imports or nonzero/absent safe workspace need separate supported
reconstruction paths. PEtite input-pointer tracing is the next concrete independent
diagnostic task; VMProtect requires a stateful guest GDI model. Neither is presented
as solved by this PECompact milestone.
