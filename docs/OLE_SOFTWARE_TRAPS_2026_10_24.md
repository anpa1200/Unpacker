# RC7 OLE metadata and bounded software-exception dispatch

## Evidence and scope

The Molebox trace proves a specific cause: actual LoadLibraryA(ole32.dll) returned
NULL, the guest stored/tested that value, did not take JNE, then pushed 217 and
called its assertion formatter. A second installed-wheel run with a real mapped
OLE32 export view passed that point and reached missing oleaut32.dll. Both named
views are therefore included in this candidate. No COM method returns invented
success: unimplemented calls, object activation, variants and native ordinal
contracts remain unsupported. No native DLL is installed or executed.

Metadata is derived from the same fixed public Wine commit as the existing
views: fd1153552d779e1ac14b0b1c48fbd1cde894eb0a. This is a declared resident guest
namespace, not a native Windows image/initializer/COM implementation. Initial
GetModuleHandle succeeds only because an actual validated PE view is resident.

The earlier diagnostic's stop request inside an invalid-instruction API callback
did not end guest execution immediately. Its first-assertion trace is an
observation capture point, not proof of an immediate stop. The 60-second outer
bound remained enforced; the guest later stopped on an explicitly unsupported
cleanup API. No API return or branch condition was overridden.

## Software-trap profile

Generic PE32 emulation can dispatch short INT3 (CC) and ICEBP (F1) through the
first registered guest x86 SEH handler. The existing PECompact access-violation
profile and its null-page protection are unchanged. Other generic programs keep
the backend's stack mapping; this change does not silently enable general AV
recovery or rewrite memory protections.

The INT3 exception record is STATUS_BREAKPOINT (80000003), with Context.Eip and
ExceptionAddress at CC. The guest handler must choose a continuation itself.
ICEBP is STATUS_SINGLE_STEP (80000004), with Context.Eip/ExceptionAddress at the
following instruction. ICEBP has zero parameters; INT3 uses Wine's native-x86
three-parameter record shape, with first parameter zero. The other two parameter
slots remain opaque and cannot be read/copied as invented zeros. Modeled API
memory copies are subject to the same guard as CPU memory instructions. These expectations
come from pinned Wine x86 regression tests/implementation, not by treating an
unsupported CPU instruction as a NOP.

No handler means an unhandled guest exception, not automatic continuation.
ContinueExecution (frame-handler disposition 0) is required. Search, unwind,
nested traps, hardware trap-flag transitions, long CD03, other interrupts,
debug/floating context payloads and DispatcherContext dereferences are explicitly
outside this profile. Unsupported interrupts stop, rather than being swallowed
by a global interrupt hook. Code/data and stack continuations must be mapped;
page-zero handlers are rejected even if the backend maps that page.

The eight-exception bound and existing decode 60 s / job 75 s / output 32 MiB
limits remain. Original/reference programs never choose or create a continuation.
No host callback or nested emu_start is used. The standard CPU loop resumes after
validated handler completion and restores the declared context/hidden CPU state.

## Evidence references

- Public metadata: Wine dlls/ole32/ole32.spec and dlls/oleaut32/oleaut32.spec at the pinned commit.
- [Wine x86 exception tests](https://github.com/wine-mirror/wine/blob/fd1153552d779e1ac14b0b1c48fbd1cde894eb0a/dlls/ntdll/tests/exception.c), ICEBP table and int3_handler.
- Local proof: ole-seh-2026-10-24/evidence/molebox-ole-causal-trace-v1/trace.json.
- Local tests: test_software_traps.py, test_guest_seh.py and metadata/loader tests.

The JDPack RC4 partial artifact is retained: 366 of 8737 executable bytes differed
from its reference. RC6's missing ulib.dll error removes that diagnostic artifact,
but did not lose a validated original recovery. It remains a compatibility gap.

## Verified focused outcomes and dispatch flags

The exact first combined installed wheel passed 649 tests and 11 package checks.
Its focused run kept PECompact's seven original-comparison gates true. TELock
and Yoda remain unsupported, and Molebox reached the hard 60-second deadline.
These are not additional accepted recoveries.

The TELock instruction trace disproves an initial flag-inheritance hypothesis:
its first ICEBP handler enters with TF=0, deliberately abandons the dispatcher
stack, restores FS:[0], installs another frame, sets TF via POPFD, then reaches
a hardware single-step. Yoda's handler deliberately installs a nested frame and
executes another INT3. Supporting either requires a broader, tested exception
model; the eight-event limit is retained, and neither trap is silently skipped.

Independently, handler entry now clears working TF/DF/AC while preserving the
fault flags in CONTEXT. Wine's pinned signal_i386.c setup_exception() clears
exactly these flags before the dispatcher. Synthetic tests verify each flag and
actual guest DF observation/restoration. This is ABI correctness, not proof that
the TELock/Yoda limitations are solved.

A diagnostic-only sampled Molebox run through 2,097,152 interpreted instructions
shows advancing decompression counters and a later LCG/XOR loop. It does not prove
the final timeout is an infinite loop or an IAT/COM failure. A 25-second hotspot
trace reached no capture point; it is retained as an inconclusive failed attempt.
