# PEtite handoff and failure-diagnostic repair

Date: 2026-10-22. Repository: `anpa1200/Unpacker`, branch `main`, base HEAD
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. Changes are local and uncommitted.

## Verified outcome

The premature PEtite handoff is fixed. The fixture **still fails to unpack**.
Its guest loader now reaches its actual `Corrupt Data!` message followed by
`ExitProcess(0xffffffff)`. No reconstructed artifact exists and no original-comparison
gate is claimed for this fixture. The result remains `failed`.

All **243 benign unit tests pass**. Seven accepted PE regressions—ASPack,
BeRoEXEPacker, MEW, MPRESS, NSPack, Packman and UPX—continue to pass all seven
original-comparison gates. JDPack remains partial with its executable-byte
mismatch; Alienyze retains its unmapped-fetch failure; VMProtect retains its
unsupported `RegisterWindowMessageA` call. These ten regressions and the separate
PEtite target share one source hash set. The 60-second decode budget and existing
isolation/output limits were retained.

The previous complete 54-fixture matrix remains **32 accepted, 6 partial and
16 unrecovered**, measured on the earlier 234-test build. A complete 54-case matrix
was not repeated for this scoped follow-up. No new accepted recovery is claimed.

## Confirmed defect and repair

The pinned backend allows PEtite execution only from its entry instruction to the
end of the loader section. In this fixture the entry is `0x40710b`, while the same
section begins at `0x407000`. A branch to `0x4070ce` therefore incorrectly triggered
a section exit and attempted to dump while the live DOS header was invalid.

`_configure_petite_unpacker` now uses the entire validated initial loader section,
with the inclusive range `0x407000..0x408794`. The next byte is outside the section.
Entry mapping must be unique and the extent must fit PE32 and the configured
dump budget. Other packers retain their existing range logic. PEtite's existing
allocation handling is preserved. No jump, return value or decoded byte is forced.

Six synthetic tests cover the internal backwards jump, the final boundary,
other-packer behavior, missing/ambiguous sections, address overflow and size limits.

## Failure evidence

The guest API model now retains its exit code and a bounded last MessageBox
diagnostic. Text is captured from guest memory only, with at most 256 ANSI bytes
or UTF-16 code units per field. Null, unmapped and unterminated strings are handled
explicitly. Diagnostic failures do not change the selected guest response or
control flow. No host GUI, filesystem path or network service is accessed.

On an exit before reconstruction the result records the exit code, last guest
message and the existing bounded CPU-state snapshot. The error is now
`Guest ExitProcess(0xffffffff) before reconstruction handoff`, rather than only
`No current-run output`. Three further synthetic tests cover bounded ANSI/UTF-16
capture, unreadable memory and termination state.

The captured PEtite dialog is `ERROR!` / `Corrupt Data!`. A separate bounded guest
trace identifies the loader's stored-block length/complement rejection before
that error branch. This proves the observed guest path; it does **not** establish
that the acquired file itself is corrupt. Loader mapping, stream interpretation
and CPU-model differences remain possible causes.

## Rejected experiment

Static inspection found nonzero file bytes at offset `0x780` where pefile's mapped
header page was zero-filled. An isolated experimental initializer copied only
the header-page tail from the packed input, with section/IAT overlap guards.
The guest still reported the same corruption failure. This did not establish a
recovery fix, and the initializer and its tests were removed from the candidate.
Its source, failure report and test output are retained as experimental evidence.
No bytes from the paired original were used to create a reconstructed artifact.

The diagnostic also reproduced a separate upstream `VirtualProtect` deficiency:
its old-protection output cell was unchanged across two calls. Microsoft's
[VirtualProtect contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
requires that output to receive the first page's previous protection. This API
deficiency was observed, but its role in the PEtite failure is unproven and it
was not presented as fixed. A faithful repair needs tracked reservation/page
protection state and corresponding tests, rather than an invented constant.

## Next engineering limitation

PEtite needs an independently validated compressed-stream interpretation and a
controlled benign fixture/reproducer to distinguish decoder-input problems from
loader/CPU behavior. The current pair is replayable but has no retained packer
invocation recipe. No validated PEtite producer or independent Windows reference
runtime is available in this test setup. Running another packer binary or a native
Windows specimen would require additional reviewed tooling/environment and
authority; neither was attempted.

The next milestone is a documented PEtite stream layout plus benign decoder
fixtures and loader-state tests, then all seven original-comparison gates on the
acquired pair. Forced corruption-check bypasses and reference-byte reconstruction
would not satisfy that milestone.

## Evidence

Evidence is saved outside the repository in `petite-evidence/`: the original and
revised failure paths, static layout comparison, bounded guest-call/control-flow
diagnostics, the rejected experiment, unit-test results and ten regression reports.
Each emulated case uses the production networkless Bubblewrap sandbox, read-only
inputs/code, a 60-second backend deadline and bounded output export. Specimens and
reconstructed executables were never launched natively. Original inputs and earlier
evidence were preserved. No third-party installation, commit, push or publication occurred.

## Follow-up classification

The [runtime follow-up](GUEST_RUNTIME_2026_10_22.md) confirms that a benign
arithmetic replay matches the observed rejection calculation. PEtite's earlier
decoder-input cause remains unresolved. Neither the error dialog nor the absence
of an independent runtime proves an unsupported-CPU or corrupt-input blocker.
The unsuccessful header-page initializer was not deployed.
