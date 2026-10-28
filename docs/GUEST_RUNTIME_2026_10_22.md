# Unpacker: guest runtime and exception-dispatch repair

Date: 2026-10-22. Repository: `anpa1200/Unpacker`, local branch `main`, base HEAD
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. Existing local changes were preserved.
No commit, push, publication, new credential access or third-party installation occurred.

## Verified result and scope

This pass delivers bounded registered-message APIs, an image-header-based process
version query, an explicit guest desktop metric profile, bounded unsupported-call
evidence, and a narrow PECompact access-violation dispatcher. It also corrects the
classification of PEtite's remaining failure: **unresolved decoder-input diagnosis**,
not a proven unsupported-CPU or unavailable-reference blocker.

**273 benign unit tests pass.** The final 12-fixture cohort shares one exact set
of 58 Python source hashes. Seven accepted PE fixtures still pass all seven
known-answer gates. JDPack remains partial. Alienyze and PEtite remain failed.
PECompact now executes its registered exception handler, reaches a rejected
reconstruction candidate and then stops at unsupported `CreateEventA`. VMProtect
advances to unsupported `GetDC`. **No new accepted recovery is claimed.**

The previous complete 54-case benchmark remains **32 accepted / 6 partial /
16 unrecovered**, measured on the earlier 234-test build. The intervening
243-test PEtite pass checked 11 fixtures; this pass checked 12. Neither scoped
cohort is a new complete-corpus benchmark.

The default decode deadline remains 60 seconds per backend. Each fixture here used
that deadline and a 75-second total job budget. Existing memory, CPU, output,
entry-count, network isolation and validation boundaries were retained.

## PEtite: what is known, rejected and unresolved

The earlier range repair remains: a jump within the initial loader section is
not a handoff. Continuing beyond that false stop reveals the guest's own
`Corrupt Data!` dialog and `ExitProcess(0xffffffff)`.

The captured input check processes word `0x0300905a`. Its low-word/complement
calculation yields nonzero `0x6ca5`, so the observed rejection branch is internally
consistent. A reviewed benign arithmetic fixture reproduces the result on the
installed Unicorn and independently checks the result with integer operations.
A complementary valid word also passes. This rules out an arithmetic/zero-flag
error in that small sequence; it says nothing definitive about earlier decoder
state, memory provenance or pointer selection.

The earlier experiment that filled missing first-header-page bytes from the packed
input did not remove the error. Its source/results are preserved outside the
deployment. That rejects the sufficiency of that initializer, not every possible
loader-mapping explanation. The error dialog does not establish that the acquired
file is corrupt. An independent producer/runtime baseline would help validation,
but its absence is not proof that further static diagnosis is impossible.

Next PEtite work is bounded data-flow tracing from the last successful block to
the rejected input pointer, then a reproducible benign stream fixture. Existing
read-only and CPU-emulation tools can support this. No corruption check was
bypassed and no reference bytes were substituted.

## Guest API models

### Registered messages

`guest_messages.RegisteredMessages` models `RegisterWindowMessageA/W` in a fresh,
isolated guest session. Supported ASCII names are bounded to 255 characters, use
one case-insensitive namespace across ANSI/UTF-16 calls, and map to stable IDs in
the documented registered-message range. At most 1,024 names are stored. Unknown
encodings, integer-atom spellings, invalid memory and exhausted model budgets stop
explicitly. Host atom tables, windows and IPC are never accessed. Evidence records
IDs and name hashes. Microsoft's [message registration contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerwindowmessagea)
and [atom-table semantics](https://learn.microsoft.com/en-us/windows/win32/dataxchg/about-atom-tables)
ground the supported profile; cross-process messaging is not implemented.

### Process version

`GetProcessVersion` returns the current input image's subsystem major/minor version,
with major in the high word. Zero and the current modeled process ID are supported;
foreign processes and invalid header metadata stop explicitly. It does not return
the host version or simply reuse the guest's Windows 7 profile. The observed
fixture reports 4.0. This follows Microsoft's [image-version contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessversion),
with subsystem-field selection corroborated by [Wine's implementation](https://github.com/wine-mirror/wine/blob/master/dlls/kernelbase/process.c).

### Desktop metrics and unsupported calls

The guest has a declared 96-DPI configuration: 32-pixel large icons and 17-pixel
scrollbar thickness. Only metrics 2, 3, 11 and 12 are supported; all other indices
stop. These are explicit simulation inputs, not measurements of the host or a
claim about every Windows configuration. The mapping uses the documented
[GetSystemMetrics identifiers](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics).

Unknown APIs now retain at most six raw guest stack words. The evidence labels
their signature as unknown; these words are not presented as verified arguments.
Unreadable stack data does not replace the original unsupported-API reason.

VMProtect now reaches `GetDC(NULL)`. A [device context](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc)
has a lifetime and state consumed by subsequent GDI operations. No dummy handle
or arbitrary drawing/query success was introduced. The fixture remains unsupported,
has no paired original in this corpus, and establishes no devirtualization result.

## PECompact: confirmed exception-path defect

Static entry inspection rejects a missing-TLS explanation: its TLS directory is
empty. The entry installs handler `0x4137b0` through `FS:[0]`, zeros EAX and executes
`mov [eax], ecx` at `0x401016`. The intended null write should fault. The old backend
maps its stack starting at address zero, allowing that store and then executing
the following `PECompact` marker bytes as instructions. The later unmapped read
at `0x802004` is therefore downstream of a suppressed exception.

The PECompact-only profile now leaves the first page unmapped while preserving
all remaining owned stack bytes and the stack pointer. Its TEB stack limit reflects
the guard. The first attempt to split the old Unicorn mapping failed with NOMEM
inside the existing address-space limit. A full owned-stack remap avoids that
allocation pattern; limits were not increased. Microsoft describes null-address
faults as [access violations](https://learn.microsoft.com/en-us/shows/inside/c0000005).

`guest_seh.AccessViolationDispatcher` calls the first validated stack-registered
handler on the existing guest CPU. It supplies a bounded exception record and
declared integer/control/segment context, preserves the full CPU state across
the handler, and resumes only after the current emulator call returns. No guest
address is invoked as a host function. The observed handler patches the guest's
faulting instruction and returns ContinueExecution; the CPU then reaches the
decompressor and import resolution.

The profile is deliberately narrow: PE32 read/write access violations, one cdecl
handler, CONTEXT_FULL, at most eight sequential faults, and ContinueExecution.
Nested faults, search/unwind, changed segments or privileged flags, and accesses to
unmodeled debug/floating-point context payloads stop. Opaque DispatcherContext and
vectored dispatch are not modeled. Other packers retain their current exception
behavior. This is a tested subset of [structured exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/about-structured-exception-handling),
not a complete Windows exception subsystem.

Synthetic CPU tests cover context continuation, integer and floating-point state
preservation, null-page guarding, nested faults, unsupported dispositions, cdecl
stack validation, privileged flags and declared segment fields. Handoffs are
disabled while a handler is active. The existing detached candidate checks are
enabled for the PECompact path and remain reference-independent.

## PECompact reconstruction is still rejected

After the handler and decompressor, a candidate appears at RVA `0x532c`. Its
entry is mapped executable data, but the rebuilt IAT fails loader readiness.
The bounded diagnostic identifies nonzero terminators at RVAs `0x25d60` and
`0x25cb1`; one contains the bytes for `user`. The candidate is deleted and the
guest continues. Later application initialization reaches unsupported
`CreateEventA`. No original-comparison success is inferred from execution progress.

Rejection details now include bounded actual/expected bytes for at most 16 IAT
mismatches. Only the latest four rejected candidates retain detail. This preserves
the same gate result while making the failed reconstruction reviewable.

Observed imports contain 92 bindings across ten groups, including seven
loader-related observations under extensionless module names. They are not simply
duplicates of the eight larger module groups: four bindings are absent there.
Blind alias deduplication or dropping an extensionless group would therefore be
an assumption. An experimental rebuilder required unique aligned zero-terminated
IAT arrays inside declared sections and excluded temporary copies. It found
ambiguity, so it was withdrawn. Its source, tests and failure are retained; no
guessed IAT was deployed and no terminator was zeroed to force acceptance.

The immediate reconstruction limitation is import-slot provenance and ambiguity.
The subsequent [event-object API](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)
would also need real guest object state and handle semantics if execution were
continued that far. Fixing the unpacking handoff takes priority over emulating
more application startup calls.

## Final scoped fixture results

| Case | Source family | Outcome | Validation | Elapsed seconds |
|---|---|---|---|---:|
| case0001 | ASPack | extracted | known_answer_verified | 14.34 |
| case0004 | BeRoEXEPacker | extracted | known_answer_verified | 5.69 |
| case0011 | MEW | extracted | known_answer_verified | 4.60 |
| case0012 | MPRESS | extracted | known_answer_verified | 30.31 |
| case0014 | NSPack | extracted | known_answer_verified | 56.00 |
| case0018 | Packman | extracted | known_answer_verified | 7.79 |
| case0022 | UPX | extracted | known_answer_verified | 1.04 |
| case0010 | JDPack | partial | partial | 3.29 |
| case0002 | Alienyze | failed | not_checked | 16.49 |
| case0017 | PEtite | failed | not_checked | 3.40 |
| case0016 | PECompact | unsupported | not_checked | 9.16 |
| case0053 | VMProtect | unsupported | not_checked | 2.59 |

The seven accepted rows pass executable bytes, entry RVA, entry mapping, imports,
loader-ready IAT, complete descriptors and machine type. JDPack's executable-byte
gate remains false. Reference inputs are validation only. All acquired specimens
were handled in the production networkless Bubblewrap sandbox and were never
launched natively. Source and input hashes bind the detailed results to this pass.

## Prioritized remaining work

| Priority | Work | Missing capability / next acceptance criterion |
|---|---|---|
| P0 | PECompact IAT provenance | Distinguish loader bindings, temporary copies and payload IAT slots with independent evidence; reject ambiguity; then pass all seven original gates. No new access is required for this local analysis. |
| P0 | PEtite input-state diagnosis | Reproduce the first wrong decoder pointer/state transition; fix from packed-input evidence and require all original gates. The current cause remains unresolved. |
| P0 | Exception-model validation | Add controlled fixtures for search, unwind, nested faults and other exception classes before broadening the current PECompact-only profile. Do not assume other CPU-fault cases share this cause. |
| P1 | VMProtect recovery criterion | Obtain paired/reproducible benign coverage and identify whether any protected code is recovered; GDI emulation alone does not establish unpacking or devirtualization. |
| P1 | Guest object models | Implement event/DC state, lifetime and dependent operations only where required by a measured recovery path; retain unsupported results for missing behavior. |
| P1 | Remaining memory/ISA faults | Diagnose Alienyze, Yoda, RLPack and TELock from their fault provenance; an invalid opcode or access alone does not prove a required dependency or corrupt input. |
| P1 | Remaining deadlines | Diagnose Amber, EXpressor, Molebox, Themida and YZPack under the approved bound. Their old timeouts are not retested successes. |
| P2 | Format/loader coverage | WinUpack needs a custom loader for malformed nonempty imports; midgetpack/pakkero need ELF recovery implementations. Optional Qiling PE32+ validation still lacks its reviewed runtime/rootfs. |
| P2 | Reproducibility | Add compiler/packer recipes and diverse known originals. Current paired fixtures are replayable but are not a reproducible packing pipeline. New unrecognized tools or native reference execution need review/authority. |

Several remaining paths are engineering work feasible with current local tools;
this report does not classify all failures as authority-blocked. Independent Windows
reference execution would require an appropriate isolated environment and additional
execution authority. No such environment was created or specimen execution attempted.

## Evidence bundle

The accompanying proof archive contains this report, final source/tests, deployment
and source hashes, the 12 detailed regression records, reviewed diagnostic drivers,
the rejected experiments and earlier benchmark summaries for context. It excludes
specimens, reconstructed executables, credentials and wheel binaries. There is no
claim that the entire corpus was rerun or that every packer can be recovered.
