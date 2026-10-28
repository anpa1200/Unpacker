# RC8 bounded PE32 stack-exception model

This is a local engineering candidate. The main checkout remains RC4; neither
publication nor universal packer coverage is claimed. Historical RC7 documentation
remains accurate for that older snapshot.

## Current architecture

`StackExceptionDispatcher` is selected only for generic PE32. PECompact retains
its separate first-handler access-violation implementation. All handlers execute
inside the same Unicorn guest CPU within the existing isolated worker.

- Separate CONTEXT/record/workspace per live level; validated FS chain and guards.
- ContinueExecution, ContinueSearch and bounded Nested disposition; guest nonlocal
  exits are detected from actual restored chain and stack, never invented jumps.
- Short INT3, ICEBP, TF single-step, four one-byte execution breakpoints with RF,
  CPU DIV/IDIV faults, explicit UD2 and invalid register-source LEA.
- 64 total exception events, 8 live levels, 32 frame-search steps, 64 KiB workspace.
  The older PECompact profile retains its 8-event cap.
- Data/I/O breakpoints, unwind/collided/vectored dispatch, extended/FPU CONTEXT and
  complete native Windows dispatcher register/stack equivalence are unsupported.

## Backend fidelity repairs

Pinned Unicorn stores DR registers without delivering execution breakpoints, and
leaves RF sticky. Explicit instruction-boundary modeling supplies those semantics.
A benign two-DIV probe also reproduces vectors 0,8 from stale internal exception
state. An authenticated full CPU context saved before DIV/IDIV is restored only
on the corresponding actual vector0. Vector8 is never reclassified as division.

The initial GetModuleHandleA IAT pointer and modeled core exports use validated
actual resident export addresses. Source/EAT/RX extent/prefix/alias/IAT identity
checks fail closed, retain provenance and skip unimplemented APIs. This is an
explicit shim model, not native DLL initialization or binary-integrity equivalence.

ReadFile/SetFilePointer operate only on already-opened virtual readonly handles
backed by supplied specimen bytes. They model short reads, EOF, independent file
positions, signed seeks, Win7 output-count contract and cleanup. Overlapped,
unbuffered, writes and arbitrary host files are unsupported.

## Evidence and limits

735 source tests and 735 installed tests plus 11 package checks pass for pilot-v8.
The exact final 54-case results are recorded separately in the stage report and
proof archive; this note does not import results from an older wheel. Reference
originals are used only after extraction for acceptance, never to repair execution.

Synthetic fixtures are source-derived from pinned Wine/Microsoft/Intel behavior.
No fresh native Windows differential oracle was available. Yoda's observed
unchanged-context INT3 repeat is an unresolved reference gap, not a reason to
advance EIP automatically. Loader progress alone is not accepted unpacking.

Existing decode60s/job75s/output32MiB limits and networkless sandbox remain.
No native specimen execution, additional credentials, private external LLM calls,
security-setting changes, commits, pushes or publication were performed.

Primary references: Microsoft exception dispatch and CONTEXT contracts; Wine
commit fd1153552d779e1ac14b0b1c48fbd1cde894eb0a x86 tests/dispatcher; Intel original
80386 debug/LEA specifications; Microsoft ReadFile and SetFilePointer docs.

## Mutex follow-up (pilot-v9)

The late TELock native address was identified as CreateMutexA, not an unknown
SEH continuation. GuestMutexes models real local single-thread object identity,
reference counts, initial ownership, recursive immediate wait/acquisition,
ReleaseMutex and CloseHandle. Existing names preserve ownership and return
ERROR_ALREADY_EXISTS. Last close destroys the object. Global/private namespaces,
inherited ACLs, external owners/threads and abandonment remain unsupported.
752 source tests pass; the exact installed/corpus result is recorded separately.

Pilot-v10 adds GetCurrentProcessId using only the existing validated backend virtual PID, with no host PID fallback;758 source tests pass. Independent installed/full-corpus evidence remains separately versioned.

Pilot-v11 adds only noninherited handles to the current unprotected guest process, retaining requested explicit rights and proper CloseHandle state. Foreign PID, generic/MAXIMUM_ALLOWED and inherited-security paths remain unsupported;765 source tests pass. No host OpenProcess/OS process lookup occurs.

Pilot-v12 adds VirtualProtectEx only for current-process/pseudo handles with PROCESS_VM_OPERATION, delegating to the existing private guest-page protection model. Both API names defer mem_protect until after the code hook and resume the caller once; real Uc probes verify stack/call count/permissions. Host memory, foreign processes, copy-on-write/guard/reserve-commit extensions remain unsupported;770 source tests pass.
