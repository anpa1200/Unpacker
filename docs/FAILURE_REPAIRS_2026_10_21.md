# Unpacker failure repairs — 21 October 2026

This is an evidence record for local engineering changes, not a universal unpacking
claim. The repository remains on main at
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`, with the prior work preserved and the
new changes uncommitted. No samples were executed natively, no specimen bytes or
credentials were sent to an LLM, and no dependencies, rootfs, samples or services
were installed or started.

## Confirmed improvements

- **ward:** a new static adapter extracts the unique uncompressed ELF carried by an
  appended PT_NOTE. It validates carrier/payload bounds, header counts, executable
  entry mapping and section extents. The acquired fixture's entire output matches
  its paired original SHA-256. Other/compressed layouts remain unsupported.
- **Ezuri:** a static adapter derives the trailer position from the bounded ELF
  file extent, then tests the format's three AES key lengths using the embedded
  key/IV and CFB128 decryption. Exactly one structurally valid ELF is required.
  The acquired fixture's entire output matches its paired original SHA-256. Keys
  and IV bytes are not logged. CFB has no authenticity check: structural acceptance
  alone is not cryptographic integrity or proof of an original file.
- **Exe32pack:** the former premature dump failed code, entry and import comparisons.
  The new path rejects that candidate, preserves the running CPU state, follows the
  later restored-code handoff and reconstructs a core passing the original static
  gates. Erased headers are inferred from retained input metadata, so the result
  remains PARTIAL even when all gates pass. The original is never used to synthesize
  output bytes or select an entry point.
- **Generic reconstruction:** import/header rewriting operates on detached image
  bytes. Rejected candidates cannot corrupt the running guest. Candidate attempts,
  rejected-key storage and retries are bounded. Reconsideration follows observed
  import progress and external writes to a code page. Live-header updates preserve
  the input's bounded zero-raw section reservations. Header erasure recovery is a
  conservative, explicitly partial path.
- **Import-table correctness:** a new acceptance gate walks the raw descriptor
  table to its null terminator and checks agreement with the parser. Best-effort
  parsing of some correct names can no longer hide malformed trailing descriptors.
  A bounded normalization step can terminate a fully validated backend-built table;
  it refuses to overwrite import names/lookup/IAT data. Already valid tables are
  preserved, including directories whose size already includes the terminator.
- **CRT and guest API contracts:** `_initterm` and `_initterm_e` now schedule real
  guest callbacks, preserving cdecl stack state, callback order, null skips,
  `_initterm_e` failure returns and nested calls. Tables, total calls and depth have
  explicit limits. Pending callbacks keep a dump partial. Added contracts cover
  the virtual process heap, heap ownership, movable allocation handles and locks,
  command-line/empty environment strings, CP1252/UTF-8 conversion, application/CRT
  cells and x87/SSE floating-point control. Unknown semantics still stop execution.
- **Diagnostics:** failed runs record bounded guest registers, instruction bytes,
  mapped-region metadata and the actual modeled call/arguments at an unsupported
  boundary. API profiles and lack of exception dispatch are explicit. This does
  not implement SEH, a full Windows runtime or protector devirtualization.
- **Documentation:** README now describes active adapters, validation, containment,
  AI scope, the empty bundled signature database and unimplemented arbitrary IAT
  discovery. Historical milestone reports are preserved.

## Validation method and limits

Tests use the existing immutable corpus: 54 packed fixtures, 32 normalized family
labels and 31 paired cases representing 12 distinct original hashes. Coverage is
mostly one specimen per family/version, with limited original-program diversity.
The artifacts are repeatable acquisitions, not reproducible source/compiler/packer
recipes.

Every acquired-input test uses the production Bubblewrap sandbox with no network,
private home or inherited credentials; read-only input/source bindings; a private
32 MiB output tmpfs; process limits; and a 30-second backend deadline. Exports are
bounded and validated before host copying. These namespace boundaries share the
host kernel and are not VM containment. Source labels are used to select a backend
in the full pass; that pass does not measure automatic detection recall. Separate
automatic tests cover the new ELF adapters.

PE paired acceptance checks executable bytes, entry RVA/mapping, imports, loader-ready
IAT values, a complete raw import-descriptor table and machine type. ELF paired
acceptance uses whole-file SHA-256 equality. Static equality is not proof of runtime
behavioral equivalence; a structurally plausible artifact can still be partial.

Benign tests cover malformed ELF metadata, wrong/truncated ciphertext, callback
execution/ABI/budgets, guest string/memory/heap behavior, snapshot isolation,
malformed/compact headers and incomplete import descriptors. No acquired specimen
is imported by the unit suite. Local wheel construction is offline and publication
has not been requested.

The first broad attempt was stopped after a new conservative validator caused
ASPack/MPRESS warnings and rejected BeRo's compact header. Those regressions were
fixed and retested before the final complete pass. Original/intermediate evidence
is retained under separate run tags; failed experiments are not counted as successes.

## Final measured results

179 benign unit/regression tests pass. All 54 acquired fixtures were tested sequentially on one recorded source snapshot, with no source changes during the pass. The results are: **extracted: 28**, **extracted_vendor_format: 3**, **failed: 7**, **partial: 6**, **timeout: 5**, **unsupported: 5**.

**15/31 paired cases** pass their original-comparison scope. Five PE cores remain partial despite passing all static gates. The 23 UPX fixtures remain accepted. These are fixture counts, not a success percentage across all packer versions.

| Case | Packer | Outcome | Paired-original evidence | Current reason |
|---|---|---|---|---|
| case0001 | ASPack | extracted | all seven static PE gates pass | — |
| case0002 | Alienyze | failed | not established | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0003 | Amber | unsupported | not established | Emulation callback stopped: UnsupportedAPI: __lconv_init: API semantics are not implemented |
| case0004 | BeRoEXEPacker | extracted | all seven static PE gates pass | — |
| case0005 | EXpressor | timeout | not established | Emulation hard deadline exceeded |
| case0006 | Enigma Virtual Box | partial | all seven static PE gates pass | Embedded virtual filesystem and wrapper TLS behavior are not reconstructed |
| case0007 | Eronana Packer | partial | all seven static PE gates pass | Degraded emulation dump |
| case0008 | Exe32pack | partial | all seven static PE gates pass | Degraded emulation dump |
| case0009 | FSG | partial | all seven static PE gates pass | Degraded emulation dump |
| case0010 | JDPack | partial | failed: executable_bytes, import_descriptors | Degraded emulation dump |
| case0011 | MEW | extracted | all seven static PE gates pass | — |
| case0012 | MPRESS | extracted | all seven static PE gates pass | — |
| case0013 | Molebox | timeout | not established | Emulation hard deadline exceeded |
| case0014 | NSPack | timeout | not established | Emulation hard deadline exceeded |
| case0015 | Neolite | partial | all seven static PE gates pass | Degraded emulation dump |
| case0016 | PECompact | failed | not established | Unmapped emulated memory access: {'access': 19, 'address': 8396804, 'size': 2} |
| case0017 | PEtite | failed | not established | No current-run output |
| case0018 | Packman | extracted | all seven static PE gates pass | — |
| case0019 | RLPack | failed | not established | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0020 | TELock | failed | not established | Emulated CPU stopped: UcError: Invalid instruction (UC_ERR_INSN_INVALID) |
| case0021 | Themida | timeout | not established | Emulation hard deadline exceeded |
| case0022 | UPX | extracted | all seven static PE gates pass | — |
| case0023 | WinUpack | unsupported | not established | Nonempty input import directory is malformed; custom loader needed |
| case0024 | Yoda-Crypter | failed | not established | Unmapped emulated memory access: {'access': 19, 'address': 8536256, 'size': 1} |
| case0025 | Yoda-Protector | failed | not established | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0026 | ezuri | extracted | exact original SHA-256 | — |
| case0027 | gzexe | extracted | exact original SHA-256 | — |
| case0028 | midgetpack | unsupported | not established | Unipacker requires a valid PE32 file |
| case0029 | pakkero | unsupported | not established | Unipacker requires a valid PE32 file |
| case0030 | upx | extracted | exact original SHA-256 | — |
| case0031 | ward | extracted | exact original SHA-256 | — |
| case0032 | UPX | extracted | not established | — |
| case0033 | UPX | extracted | not established | — |
| case0034 | UPX | extracted | not established | — |
| case0035 | UPX | extracted | not established | — |
| case0036 | UPX | extracted | not established | — |
| case0037 | UPX | extracted | not established | — |
| case0038 | UPX | extracted | not established | — |
| case0039 | UPX | extracted | not established | — |
| case0040 | UPX | extracted_vendor_format | not established | — |
| case0041 | UPX | extracted_vendor_format | not established | — |
| case0042 | UPX | extracted | not established | — |
| case0043 | UPX | extracted | not established | — |
| case0044 | UPX | extracted | not established | — |
| case0045 | UPX | extracted | not established | — |
| case0046 | UPX | extracted_vendor_format | not established | — |
| case0047 | UPX | extracted | not established | — |
| case0048 | UPX | extracted | not established | — |
| case0049 | UPX | extracted | not established | — |
| case0050 | UPX | extracted | not established | — |
| case0051 | UPX | extracted | not established | — |
| case0052 | UPX | extracted | not established | — |
| case0053 | VMProtect | unsupported | not established | Emulation callback stopped: UnsupportedAPI: RegisterWindowMessageA: API semantics are not implemented |
| case0054 | YZPack | timeout | not established | Emulation hard deadline exceeded |

The machine-readable matrix, per-case reports, input hashes, invocation/budget records, source hashes and bounded logs are retained in the proof archive. Specimen/output binaries are excluded from the archive.

## Remaining engineering

This pass does not fix every recovery failure. The matrix below records actual
outcomes and exact current stopping reasons. Missing decoders, loader/exception/CPU
semantics and runtime APIs require further implementation and validation; increasing
timeouts or renaming a backend is not proof of recovery. Existing tools permit more
static investigation and model development; no access-denial or approval block is
being represented as the cause of those engineering gaps.

- Amber executes its first CRT initializer and then stops at `__lconv_init`; locale/
  CRT data initialization remains unimplemented. Callbacks are implemented, not skipped.
- VMProtect progresses through startup, code-page, environment and movable-memory
  calls, then reaches an unsupported GUI/runtime API. There is no paired original
  for this fixture, so a future dump would not establish complete recovery.
- JDPack still has executable-byte differences, inferred execute permissions and an
  incomplete descriptor table. It remains partial; no equality mask hides them.
- Remaining CPU exceptions, invalid instructions and unmapped reads have bounded
  diagnostics. These symptoms alone do not establish a unique root cause. Exception
  dispatch, compatible loaders or instruction handling may be required.
- Timed-out loaders/protectors need bounded profiling and packer-specific recovery
  work. There is no proof they would recover with a larger budget.
- midgetpack and pakkero lack compatible payload decoders. Static layout was inspected;
  no original was substituted and no unknown software was executed to claim support.
- Optional PE32+ Qiling/rootfs integration remains unavailable. Arbitrary standalone
  IAT discovery is still a stub. Existing retained/import-observation recovery does
  not imply that missing capability.

## Primary references

- [ward injector's appended PT_NOTE layout](https://github.com/ex0dus-0x/ward/blob/main/injector.go)
- [Ezuri writer's appended key/IV/ciphertext layout](https://github.com/guitmz/ezuri/blob/master/ezuri.go)
- [Independent Ezuri unpacker](https://github.com/f0wl/ezuri_unpack)
- [Cryptography symmetric-cipher API](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)
- [Microsoft CRT initializer contracts](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e?view=msvc-170)
- [Microsoft floating-point control contracts](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/control87-controlfp-control87-2?view=msvc-170)
- [Microsoft WideCharToMultiByte contract](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
- [Microsoft GetProcessHeap](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap)
- [Microsoft SetHandleCount](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-sethandlecount)

These references establish selected formats/contracts, not compatibility with every
version or a claim to full operating-system behavior.
