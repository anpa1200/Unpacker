# Unpacker: resumed development and validation — 2026-10-21

Source repository: `anpa1200/Unpacker`; branch `main`; HEAD `29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. Changes remain local and uncommitted. The source hashes in this evidence package identify the modified build more precisely than HEAD alone.

## Outcome

The final sequential 54-case run produced **30 accepted outputs, 6 partial outputs and 18 unrecovered cases**. Detailed status counts: extracted=27, extracted_vendor_format=3, failed=7, partial=6, timeout=7, unsupported=4.

This pass repairs concrete import reconstruction and emulator-process defects. It does not establish universal packer support. Packer labels come from upstream datasets, and most non-UPX families have one fixture/version. The corpus has 31 packed/original pairs but only 12 distinct original hashes. Source-label backend overrides are used for this corpus pass, so it does not measure automatic-detection recall.

## Implemented repairs

### JDPack: corroborated recovery of erased import names

`src/unpacker/pe_rebuilder/erased_names.py` recognizes retained PE32 descriptor/lookup/IAT skeletons. Every function name comes from one unique observed guest module/address binding. The path requires separate lookup and address tables, strict names and ordinal agreement, null termination, bounded table/symbol counts, file-backed section bounds, no overwrite of nonzero names, no name/control-data overlap and one unique maximal candidate. It restores bytes only in the detached reconstruction snapshot; paired originals are never consulted by extraction.

On `case0010`, all **84 erased names** were recovered, and the four-descriptor table now passes the raw descriptor-completeness gate. Executable-section differences from the original fell from **2,532 to 366 bytes**. A separate bounded static diagnostic accounts for all 366: **334 IAT bytes** changed from bound addresses to loader-ready lookup RVAs, and **32 descriptor timestamp/forwarder bytes** were cleared for the unbound reconstruction. No other bytes differ in the original executable section.

The original strict `executable_bytes` gate remains false; it was not relaxed. JDPack stays **partial** because execute permission was inferred and full relocation/runtime equivalence is not established. A parser-visible list of import names is not enough evidence by itself.

### PE32 process loader metadata

`src/unpacker/loader_lists.py` replaces the backend's three-DWORD placeholder entries with bounded PE32 loader records for the already mapped executable, ntdll, kernel32 and KernelBase. It provides separate circular doubly linked lists, valid Unicode module names with byte lengths/terminators, mapped module bases, entry points and declared image sizes. It does not load or initialize another DLL, execute module initialization, expose host libraries, or implement the rest of the Windows process ABI. Existing snapshot padding remains unchanged.

Amber previously read a zero module-name length and underflowed its guest loop until unmapped memory. With corrected records it traverses module exports and resolves additional imports. A separate 60-second development run reached **6,160,384 sampled instructions and 19 GetProcAddress calls**. It still exceeded the deadline and produced no accepted output. The final corpus keeps the original 30-second budget. Alienyze moved past its prior CPU exception to MessageBoxW and then an invalid instruction fetch; it remains unrecovered.

### Explicit, bounded guest CRT models

`crt_startup.py` models legacy MSVCRT PE32 C-locale state, the locale initializer, a one-argument virtual command line, an empty guest environment and startup allocation mode. `__getmainargs` observes the cdecl stack convention. Exit callbacks can be registered with a bounded list and valid guest executable targets; CRT exit-callback dispatch remains unsupported.

`crt_memory.py` provides guest-owned malloc/calloc/realloc/free. It handles zero-sized allocations, size_t multiplication overflow, calloc zeroing, aggregate quotas, guest errno, pointer ownership, realloc prefix preservation and failure retaining the old block. A required but unimplemented new-handler path stops explicitly. It never returns host pointers.

`crt_buffers.py` provides bounded guest strlen, memcpy, memmove, memset, memcmp, strcmp, strcpy and strncpy. String scans stop at page boundaries, unbounded strings have a one-MiB ceiling, copies respect the model budget, strncpy preserves truncation/zero-padding semantics, and undefined overlap in memcpy/strncpy is rejected.

HeapFree and HeapSize now consistently accept HEAP_NO_SERIALIZE in the declared single-thread model. MessageBoxW uses the existing guest-only dialog model, preserving stdcall stack cleanup. Multiple-button choices are declared noninteractive approximations; no native UI is opened.

### Timeout evidence

Worker progress now includes bounded sampled CPU registers, instruction bytes and at most 32 mapped-region records. A hard deadline still terminates the owned worker. The snapshot is sampled progress, not proof of the final instruction at termination.

### Performance evidence and retained experiments

MPRESS passed the early paired regression in 27.55 seconds, but timed out at 30 seconds in the final full pass. The timeout occurred near the end of its four-million-instruction decoding path, before import resolution. A bounded section-label cache experiment passed all gates at 28.28 seconds, compared with an earlier uncached 27.55-second pass; that did not establish a repeatable speed gain. The optimization was removed. Its prototype, tests and measurements are preserved as experimental evidence, and no cache code remains in the deployed package. The full-pass timeout is retained in the matrix rather than replaced with an earlier passing result.

## Validation and scope

The reviewed benign test suite passes **217 tests**. Added tests use generated memory/header/string data, cover positive contracts and malformed/ambiguous evidence, and do not execute acquired specimens. The full corpus was run sequentially with the existing networkless Bubblewrap sandbox, private capacity-limited tmpfs, read-only inputs/runtime/code, process-group supervision and unchanged 30-second backend/45-second job budgets. No acquired input was executed natively. Hashes of all 85 input/reference files still match the acquisition manifest.

PE reference checks retain seven gates: exact executable-section bytes, entry RVA, file-backed executable entry mapping, import identities, loader-ready IAT, complete raw import descriptors and machine type. ELF paired recovery uses whole-file SHA-256 equality. Accepted outputs and static gates do not prove behaviorally runnable programs. Emulated artifacts stop for analyst review. No new dependencies or specimens were installed/downloaded; no external LLM calls, source publication, commits or pushes were made.

## Final per-fixture results

| Case | Upstream family | Status | Paired validation |
|---|---|---|---|
| case0001 | ASPack | extracted | 7/7 strict PE gates |
| case0002 | Alienyze | failed | not_checked |
| case0003 | Amber | timeout | not_checked |
| case0004 | BeRoEXEPacker | extracted | 7/7 strict PE gates |
| case0005 | EXpressor | timeout | not_checked |
| case0006 | Enigma Virtual Box | partial | 7/7 strict PE gates |
| case0007 | Eronana Packer | partial | 7/7 strict PE gates |
| case0008 | Exe32pack | partial | 7/7 strict PE gates |
| case0009 | FSG | partial | 7/7 strict PE gates |
| case0010 | JDPack | partial | executable_bytes failed |
| case0011 | MEW | extracted | 7/7 strict PE gates |
| case0012 | MPRESS | timeout | not_checked |
| case0013 | Molebox | timeout | not_checked |
| case0014 | NSPack | timeout | not_checked |
| case0015 | Neolite | partial | 7/7 strict PE gates |
| case0016 | PECompact | failed | not_checked |
| case0017 | PEtite | failed | not_checked |
| case0018 | Packman | extracted | 7/7 strict PE gates |
| case0019 | RLPack | failed | not_checked |
| case0020 | TELock | failed | not_checked |
| case0021 | Themida | timeout | not_checked |
| case0022 | UPX | extracted | 7/7 strict PE gates |
| case0023 | WinUpack | unsupported | not_checked |
| case0024 | Yoda-Crypter | failed | not_checked |
| case0025 | Yoda-Protector | failed | not_checked |
| case0026 | ezuri | extracted | known_answer_verified |
| case0027 | gzexe | extracted | known_answer_verified |
| case0028 | midgetpack | unsupported | not_checked |
| case0029 | pakkero | unsupported | not_checked |
| case0030 | upx | extracted | known_answer_verified |
| case0031 | ward | extracted | known_answer_verified |
| case0032 | UPX | extracted | structurally_valid |
| case0033 | UPX | extracted | structurally_valid |
| case0034 | UPX | extracted | structurally_valid |
| case0035 | UPX | extracted | structurally_valid |
| case0036 | UPX | extracted | structurally_valid |
| case0037 | UPX | extracted | structurally_valid |
| case0038 | UPX | extracted | structurally_valid |
| case0039 | UPX | extracted | structurally_valid |
| case0040 | UPX | extracted_vendor_format | vendor_validated |
| case0041 | UPX | extracted_vendor_format | vendor_validated |
| case0042 | UPX | extracted | structurally_valid |
| case0043 | UPX | extracted | structurally_valid |
| case0044 | UPX | extracted | structurally_valid |
| case0045 | UPX | extracted | structurally_valid |
| case0046 | UPX | extracted_vendor_format | vendor_validated |
| case0047 | UPX | extracted | structurally_valid |
| case0048 | UPX | extracted | structurally_valid |
| case0049 | UPX | extracted | structurally_valid |
| case0050 | UPX | extracted | structurally_valid |
| case0051 | UPX | extracted | structurally_valid |
| case0052 | UPX | extracted | structurally_valid |
| case0053 | VMProtect | unsupported | not_checked |
| case0054 | YZPack | timeout | not_checked |

## Remaining engineering work

- **Amber:** reflective allocation/handoff discovery and faster measured export-resolution/emulation. Startup APIs and loader traversal now advance, but no final recovered program is proven.
- **Alienyze:** trace the invalid instruction fetch after the modeled Unicode dialog, distinguish an intended failure path from a loader/exception-model deficiency, and validate recovery without forcing a success branch.
- **JDPack:** preserve the explicit raw equality failure while validating relocation metadata and behavior separately. Do not copy bound addresses or metadata from the reference to improve a score.
- **PECompact, RLPack, TELock and the Yoda variants:** investigate the recorded access/instruction/exception faults. The current data does not prove an anti-debugging root cause; SEH/exception dispatch remains absent.
- **EXpressor, Molebox, NSPack, Themida and YZPack:** packer-specific decoder/handoff diagnosis within containment. Longer budgets alone are not a correctness fix.
- **WinUpack and PEtite:** custom-loader/header/handoff work. WinUpack still has a malformed nonempty input import directory.
- **midgetpack and pakkero:** actual ELF payload decoders remain missing. No generic ELF success is claimed.
- **VMProtect:** the recorded guest API/runtime boundary remains incomplete; devirtualized semantics and full recovery are not established.
- **PE32+ and alternate Windows runtime coverage:** require a separately validated backend/rootfs; Qiling and a rootfs are absent in the current environment. No new runtime was installed.
- **Coverage quality:** generate a benign source/compiler/packer fixture matrix with licensed, recognized tools. The existing paired files are replayable evidence, not reproducible build recipes. Additional packer versions, corrupted/overlapping structures and behavioral validation need independent fixtures.

Standalone arbitrary IAT rebuilding remains unimplemented. The observed/retained-table paths above are narrower capabilities. Bundled signature loading is available but its database is empty. GUI, process parameters, general exception handling and CRT exit dispatch remain incomplete.

The next engineering milestone is a reflective-image discovery/serialization path with generated PE fixtures, strict bounds and import evidence, followed by a demonstrated Amber paired recovery. Existing failure evidence is retained for comparison; none of these remaining cases is presented as completed.

## Primary contract references

- [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format): import lookup/address tables and binding metadata.
- [Microsoft PEB_LDR_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data): loader lists, DLL bases and Unicode module names. Internal structures are version-specific.
- [Microsoft __getmainargs](https://learn.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs?view=msvc-170), [malloc](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/malloc?view=msvc-170), [realloc](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/realloc?view=msvc-170), [calloc](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/calloc?view=msvc-170).
- [Microsoft _onexit](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/onexit-onexit-m?view=msvc-170) and [MessageBoxW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw).
- [Microsoft HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree) and [HeapSize](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsize).
- [Wine MSVCRT locale source](https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/locale.c): independently implemented legacy locale-initializer behavior. New model code is independently written; no Wine implementation was copied.

## Focused recheck on the final source

MPRESS: `extracted`, validation `known_answer_verified`, 28.57 seconds under the same 30-second backend limit. Gates: `{'executable_bytes': True, 'entry_rva': True, 'entry_mapping': True, 'imports': True, 'iat_loader_ready': True, 'import_descriptors': True, 'machine': True}`. This is a separate observation and does not overwrite the complete 54-case cohort above.
