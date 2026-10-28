# Extraction reliability and security boundaries

Version 1.1 introduces correctness and containment controls derived from the 54-file,
32-family validation corpus. No finite corpus establishes universal unpacking coverage.

## Recommended invocation

```bash
unpacker-sandbox sample.bin -o evidence --allow-emulation --timeout 30
# Optional known-original validation:
unpacker-sandbox sample.bin -o evidence --allow-emulation --reference original.bin
```

The Linux entry point requires Bubblewrap and fails closed if namespace isolation
cannot start. It exposes read-only runtime/source/input, a private output directory,
no network, no private home or API keys, dropped capabilities and a bounded temporary
filesystem. Output uses a separate capacity-limited tmpfs (128 MiB by default);
there is no writable host output bind during analysis. After workers terminate,
a bounded uncompressed archive is exported, validated and copied as non-executable
regular files. Links, traversal, duplicate paths and oversized exports are rejected.
It records commands and process results beside `report.json`.
The direct `unpacker` command and Python API remain low-level interfaces: resource
limits and subprocess isolation are not a security sandbox. Use an isolated VM for
hostile specimens when kernel/emulator risk is unacceptable. There is no host fallback
when `unpacker-sandbox` setup fails.

Sample instructions may execute inside an emulator only after explicit opt-in.
No path launches the sample as a native process. `upx` is a native parser/decompressor
and still requires isolation for hostile data. No external LLM is given a sample or
execution authority by these changes.

## Correctness fixes

- Filename and directory labels never create detection evidence or override scores.
- UPX marker candidates are verified with bounded native integrity checks, covering
  stripped ELF and vendor-supported non-PE formats. Incidental strings are insufficient.
- Unsupported format, parser failure, method failure and no packing evidence are
  different outcomes; original input is never advertised as an extracted artifact.
- PE imports are explicitly parsed before the small-import heuristic. One-section
  files no longer trigger the last-section heuristic automatically.
- Every backend attempt gets a private directory. No shared-directory search, stale
  dump reuse or unrelated broken-import temporary file is accepted as success.
- Outputs must be owned regular files, nonempty, size-bounded, changed from the input,
  and structurally valid for their declared kind. References optionally compare original
  meaningful executable bytes, imports and executable/file-backed entry mapping.
  `reconstruction_acceptance` reports each gate, code hashes and import differences.
  Valid PE structure is not proof
  that every protected code path has been recovered.
- Emulators run in supervised child processes with hard deadlines, termination/reaping,
  environment clearing and POSIX memory/file/CPU limits. No daemon thread continues
  writing after a result is returned. Child logs are bounded.
- Unipacker's interactive post-dump pause terminates a batch engine instead of waiting
  for a human to resume. Initialization errors become typed failed/unsupported outcomes.
- Missing pages, removed imports and reconstruction errors remain recorded degradations.
  The memory-read patch enforces the dump-size budget.
- Qiling output is explicitly a partial memory snapshot; no all-zero dump can become a
  successful reconstructed executable. Rootfs selection is explicit and architecture
  directory selection does not fall back from x64 to x86.
- Owned static detection and artifact validation run in child processes with a hard
  deadline (up to 10 seconds, bounded by the remaining stage/job budget). Worker failure
  cannot leave an unchecked artifact accepted. Explicit caller-supplied parser objects
  and low-level parser helpers remain advanced in-process interfaces.
- Direct extraction APIs count aggregate allocated/logical bytes and entries across
  retained layers, with a 50 ms child watchdog and pre/post acceptance checks. This
  watchdog may overshoot between checks; use the sandbox entry point for a strict
  output filesystem capacity limit.
- Layer records retain input/output hashes and their own detection, separate from
  initial/final detection. Unchanged/cyclic output, residual heuristic evidence,
  emulation review, depth limit and job deadline have distinct stop reasons.
- Standalone IAT rebuilding is not implemented and a request for it is rejected,
  rather than silently ignored. Backend import reconstruction is separately reported.

The emulator may infer execute permission for a file-backed entry section from its
handoff. Such a repair is logged and remains a partial result even if known-original
static gates pass. It is not a claim of original permissions or complete behavior.

## Coverage expansion

Native UPX is the preferred route for integrity-verified candidates. Gzip shell wrappers
are decompressed without running their shell text, using bounded gzip decoding.
MPRESS and unknown/custom x86 PE32 candidates can use the common Unipacker path when
emulation is permitted. This exposes upstream backend capabilities; it does not certify
every packer/version supported. Unsupported input, missing imports, API gaps and partial
reconstruction remain explicit outcomes. ELF protectors beyond supported UPX/gzip routes,
x64 protector reconstruction and virtualization recovery remain substantial gaps.

## Sequential packer repairs

The [current fixture ledger](SEQUENTIAL_PACKER_RESULTS_2026_10_21.md) records the
ordered full-corpus pass, subsequent targeted fixes, exact remaining gaps and budgets.
Generic PE32 routing observes actual loader ranges, ignores loader-only/self-modifying
transitions and reconstructs imports at a candidate image handoff. A unique retained
import table is preferred only when both its symbols and live IAT bindings match the
observed API results; ambiguous data falls back to backend reconstruction.

The bounded single-thread API model never opens guest paths on the host. It models
self-file bytes, owned fixed allocations/heaps, TLS and selected process state, with
an explicit Windows 7 SP1 profile. Unsupported semantics stop the engine explicitly,
including when old ctypes callbacks would otherwise swallow exceptions. Nonempty CRT
initializer callbacks are not skipped. Instruction-cache approximation is recorded
and keeps affected results partial. This is not a Windows compatibility layer.

## Configuration and signatures

`unpacker --config config/config.yaml` loads bounded YAML explicitly (install `[config]`).
CLI flags override supported settings; unknown fields, wrong types and unimplemented
options are rejected. No home-directory config or credentials are sourced automatically.

`SignatureDetector(signatures_dir=...)` supports bounded JSON arrays of objects with
`packer_id`, hex `pattern`, and integer `offset`; `-1` maps the PE entry point to its
file offset. There is no bundled rule collection and no claim of PEiD database
compatibility or calibrated probability. Signature files, rule counts and pattern
lengths are capped. Invalid databases produce inconclusive analysis diagnostics.

## Safer acquisition

The optional acquisition script retains encrypted archives by default. `--extract`
explicitly permits one bounded member in a fresh quarantine directory; archive paths
are never used as host destination paths. Traversal/ambiguous/multiple members,
expansion limits and requested sample digest mismatches are rejected. Samples use
non-executable permissions and neutral `.bin` names. The script is an opt-in network
acquisition workflow, not a prerequisite for tests. `--dry-run` queries metadata and
is not an offline mode. Public source labels are not independent ground truth.

## Result semantics and limits

`UnpackResult.success` means the backend produced an accepted extraction artifact;
it is not a guarantee of full unpacking or runnable behavior. Inspect `status`,
`artifact_kind`, `validation_status`, warnings and report stop reason. Emulation
artifacts terminate automatic layering for review; known-answer comparisons are
stronger than structural validation. Partial artifacts can remain useful evidence.

Limits: the namespace sandbox is Linux-specific; Qiling/rootfs availability is not
bundled. Strict aggregate output capacity applies to `unpacker-sandbox`; the direct
API uses a watchdog rather than a filesystem quota. Entry count enforcement is a
watchdog/export gate, not a kernel inode quota. Host evidence and bounded archive
spooling add finite storage overhead beyond the artifact budget. Static deadlines
cover owned high-level detection/validation, not caller-supplied parsed objects,
individual low-level helpers or third-party plugins. The sandbox entry point owns
the external deadline across the entire job. Additional packer adapters and
reconstruction techniques require separate known-answer tests.

## Release checks

The package version is 1.1.0. Publish now depends on offline tests and a built-wheel
smoke test outside the checkout, then publishes that same validated artifact.
Duplicate versions fail rather than being silently skipped. No release or push is
performed by the local hardening task. Optional backend integration remains separately
measured from unit tests; no live malware/emulator jobs run in public PR CI.

## Subsequent failure-repair pass

See [the failure-repair ledger](FAILURE_REPAIRS_2026_10_21.md) for static ward/Ezuri
recovery, guest CRT callbacks, bounded process/code-page/floating-point models,
movable allocation handles, detached image reconstruction, conservative retained-input
header recovery and import-descriptor completeness checks. Earlier counts and outcomes
in this document describe their original milestone, not the current coverage matrix.

The [resumed-development ledger](RESUMED_DEVELOPMENT_2026_10_21.md) records the
subsequent JDPack import-name repair, PE32 loader-list correction and bounded CRT
models. Erased names are restored only from unique observed module/address bindings
in a retained descriptor/lookup/IAT skeleton. Unknown or conflicting evidence is
rejected. Process parameters, SEH dispatch and CRT exit-callback dispatch remain
unimplemented. Timeout reports retain a bounded sampled CPU state; they do not
claim that the final instruction at termination was captured.
