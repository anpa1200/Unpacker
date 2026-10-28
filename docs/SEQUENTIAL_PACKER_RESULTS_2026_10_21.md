# Sequential packer repairs and results — 21 October 2026

This pass worked through every existing acquired fixture in order, one at a time.
All 54 fixtures across 32 normalized source-family labels have a recorded result.
The 31 packed/original pairs represent only 12 distinct original hashes; results
are fixture-level evidence, not independent programs or version-wide coverage.

## Concrete improvements

- **BeRoEXEPacker and Packman:** corrected generic initial loader ranges, import
  reconstruction selection and premature handoff triggers. Both now pass original
  executable-byte, entry, import, IAT and machine checks.
- **MPRESS:** bounded live-image dumping and duplicate-trigger handling now recover
  the paired fixture within its 30-second budget. Repeated checks took about 26–27 s;
  no cross-machine performance guarantee follows from this one fixture.
- **Enigma Virtual Box:** a narrow static retained-core extractor validates the
  dormant import table and wrapper TLS layout from the input, restores 67 imports,
  removes wrapper sections/TLS and recovers a core passing all static original gates.
  Embedded virtual filesystem/wrapper behavior remains outside scope, so PARTIAL.
- **Neolite:** modeled read-only access to the specimen's own file, self module
  handles, mapped views and bounded allocation/free behavior enable a core passing all
  static gates. Instruction-cache flushing is approximated by this installed backend;
  that warning keeps the result PARTIAL.
- **Eronana:** reconstruct the contiguous live image rather than an allocation high
  water mark containing holes. Restore a unique retained import table only when its
  symbols AND current IAT values match dynamically observed bindings. This recovers
  `_CorExeMain` without rewriting original executable-section bytes. All static gates
  pass, but omitted noncontiguous live allocations keep the result PARTIAL.
- **Shared correctness:** single-shot dumps; bounded progress evidence for timeouts;
  explicit callback termination because old Unicorn ctypes callbacks can swallow
  Python exceptions; precise unmapped-memory/CPU error reporting; valid importless
  PE32 initialization without accepting malformed nonempty import directories.
- **Acceptance:** import-name equality alone is insufficient. A reconstructed IAT
  must contain loader-ready lookup values and terminators. Reports include bounded
  byte-difference locations and individual gate outcomes.

The paired original is used only by validation. Neither retained-import recovery nor
Enigma extraction reads it to synthesize output.

## API model scope

The added model executes no native specimen code and never opens a guest path on
the host. The only backing bytes are the supplied specimen. Unknown virtual paths
are absent and return file-not-found; no host device, filesystem or network is
queried. Self-file maps, fixed allocations and heap objects have explicit budgets.
The model is an intentionally limited single-thread environment, with 64 TLS slots,
bounded critical-section recursion and an explicit Windows 7 SP1 version profile.
No parent environment, credentials or console handles are inherited.

Message-box choices are deterministic and recorded. Nonempty CRT initializer tables
are rejected; guest callbacks are never silently skipped. Unknown API semantics stop
execution. Thus previously plausible dumps can now become explicit unsupported or
failed outcomes rather than false successes.

The selected contracts follow primary documentation: [GetModuleHandleA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea),
[CreateFileMappingA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga),
[MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile),
[MessageBox](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox),
[TlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc),
[TlsGetValue](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue),
[OSVERSIONINFOEXA](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa), and
[EnterCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection).
These links establish selected API semantics, not full Windows compatibility.

## Verification and interpretation

125 benign unit/regression tests pass. The final local wheel builds offline.
One complete 54-case ordered pass was followed by targeted runs for the reproduced
API/import gaps and regression checks on successful cases. The matrix selects the
latest relevant evidence for each case; each run records source hashes, commands,
input hashes, budgets and its original-comparison results. A frozen full-pass source
snapshot and the final source are retained. The 54-case pass used source-label
backend overrides: it does not measure automatic detector recall. UPX remains 23/23
accepted across acquired fixtures; three vendor formats have vendor validation.

Latest composite outcomes: **extracted: 26**, **extracted_vendor_format: 3**, **failed: 7**, **partial: 6**, **timeout: 5**, **unsupported: 7**.

12 paired cases have all static PE gates or an exact original file hash. Four of those cores remain PARTIAL for declared limitations. Extraction status is not proof of behavioral completeness.

## Per-fixture ledger

| Case | Packer | Outcome | Original proof / failed gates | Remaining reason |
|---|---|---|---|---|
| case0001 | ASPack | extracted | all static PE gates pass | — |
| case0002 | Alienyze | failed | not established | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0003 | Amber | unsupported | not established | Emulation callback stopped: UnsupportedAPI: _initterm: Nonempty guest CRT initializer callbacks require callback execution support |
| case0004 | BeRoEXEPacker | extracted | all static PE gates pass | — |
| case0005 | EXpressor | timeout | not established | Emulation hard deadline exceeded |
| case0006 | Enigma Virtual Box | partial | all static PE gates pass | Embedded virtual filesystem and wrapper TLS behavior are not reconstructed |
| case0007 | Eronana Packer | partial | all static PE gates pass | Degraded emulation dump |
| case0008 | Exe32pack | partial | failed: executable_bytes, entry_rva, imports | Emulated dump has no reconstructed imports |
| case0009 | FSG | partial | all static PE gates pass | Degraded emulation dump |
| case0010 | JDPack | partial | failed: executable_bytes | Degraded emulation dump |
| case0011 | MEW | extracted | all static PE gates pass | — |
| case0012 | MPRESS | extracted | all static PE gates pass | — |
| case0013 | Molebox | timeout | not established | Emulation hard deadline exceeded |
| case0014 | NSPack | timeout | not established | Emulation hard deadline exceeded |
| case0015 | Neolite | partial | all static PE gates pass | Degraded emulation dump |
| case0016 | PECompact | failed | not established | Unmapped emulated memory access: {'access': 19, 'address': 8396804, 'size': 2} |
| case0017 | PEtite | failed | not established | No current-run output |
| case0018 | Packman | extracted | all static PE gates pass | — |
| case0019 | RLPack | failed | not established | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0020 | TELock | failed | not established | Emulated CPU stopped: UcError: Invalid instruction (UC_ERR_INSN_INVALID) |
| case0021 | Themida | timeout | not established | Emulation hard deadline exceeded |
| case0022 | UPX | extracted | all static PE gates pass | — |
| case0023 | WinUpack | unsupported | not established | Nonempty input import directory is malformed; custom loader needed |
| case0024 | Yoda-Crypter | failed | not established | Unmapped emulated memory access: {'access': 19, 'address': 8536256, 'size': 1} |
| case0025 | Yoda-Protector | failed | not established | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0026 | ezuri | unsupported | not established | Unipacker requires a valid PE32 file |
| case0027 | gzexe | extracted | exact original SHA-256 | — |
| case0028 | midgetpack | unsupported | not established | Unipacker requires a valid PE32 file |
| case0029 | pakkero | unsupported | not established | Unipacker requires a valid PE32 file |
| case0030 | upx | extracted | exact original SHA-256 | — |
| case0031 | ward | unsupported | not established | Unipacker requires a valid PE32 file |
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
| case0053 | VMProtect | unsupported | not established | Emulation callback stopped: UnsupportedAPI: SetHandleCount: API semantics are not implemented |
| case0054 | YZPack | timeout | not established | Emulation hard deadline exceeded |

## Remaining work and exact limits

- Amber: nonempty guest CRT initializer callbacks need callable guest execution
  scheduling. Current tools permit implementing it, but it is not implemented.
- VMProtect PE32: current startup reaches unsupported SetHandleCount. Further CRT/API
  and virtualization handling remain; there is no paired original for this fixture,
  so a future dump alone cannot establish completeness.
- JDPack: entry/import/IAT checks pass but executable bytes differ, and execute
  permission is inferred. The output remains partial; no equality mask hides differences.
- Exe32pack: no accepted reconstruction of original code/imports/entry.
- NSPack, EXpressor, Molebox, Themida and YZPack: exceed the tested 30-second budget.
  Bounded progress records distinguish ongoing instruction execution from missing APIs;
  they do not prove eventual recovery. Dedicated decoding/control-flow work remains.
- Alienyze, RLPack and Yoda-Protector: emulated CPU exceptions; TELock: invalid
  instruction; PECompact and Yoda-Crypter: unmapped memory. Root cause is not uniquely
  established by those symptoms. Loader, exception or instruction-model work needs
  further investigation; returning invented values would not constitute a fix.
- PEtite: current trigger encounters invalid image headers and yields no current-run
  output. A packer-specific handoff/header-recovery path remains absent.
- WinUpack: malformed nonempty import data requires a custom compatible loader.
- ezuri, midgetpack, pakkero and ward: no suitable ELF extraction adapters.
- PE32+ protector validation still lacks the optional Qiling runtime/rootfs. Standalone
  IAT discovery/rebuilding remains a stub; this pass implements validated retention
  and the existing backend's observed-import reconstruction, not arbitrary IAT recovery.

Further static analysis, model development and fixture testing are feasible with the
current tools. A full Windows runtime, richer exception/multithread support and new
known-original fixtures are separate engineering/infrastructure work. No external software, dependencies,
credentials, rootfs or samples were installed/acquired in this pass. No action was
blocked by approval review. Changes remain local and uncommitted; no publication.
