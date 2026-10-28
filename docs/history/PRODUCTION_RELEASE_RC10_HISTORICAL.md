> Historical publication copy. Dated results are not current readiness. Private paths are redacted and relative links repaired; see [current status](../CURRENT_STATUS.md). Original local receipts remain preserved.

# RC10 production decision and operations

This document is authoritative for candidate1.2.0rc10. Historical version hashes, test counts and60/75-second profiles in `history/` describe previous artifacts only. Final wheel/sdist hashes, source inventory and actual checks are in the external RC10 release manifest to avoid circular self-hashing.

## Current decision

**NO-GO for production on the current host.** A scoped Linux analyst release also remains blocked until its final gate ledger is approved. Preparing a candidate does not authorize publication, deployment or changes to host security.

Required gates:

1. Approved dedicated disposable worker and patched Bubblewrap. The host has0.9.0-1ubuntu0.3; its changelog explicitly removes the CVE-2026-87766 fix. The official signed noble-security package index checked2026-10-25 contains that same revision. Upstream fixes the issue in0.12.0. The CLI conservatively requires>=0.12.0, rejects setuid/setgid/world-writable launchers, and has no bypass. A future verified distribution backport requires an explicit reviewed code policy update; a low version alone is not evidence that every distribution is vulnerable.
2. Cgroup-v2 group-wide memory/PID/CPU enforcement, cancellation of escaped process groups, finite cleanup, networkless namespaces and credential-free environment. Synthetic benign tests exercise mechanisms, not proof against every hostile escape. Operator acceptance of the outer disposable boundary remains necessary.
3. Advisory and license disposition. Seven flagged dependency versions were replaced. The raw registry gate still flags runtime setuptools80.10.2. Its retained legacy-engine requirement and Linux-only platform analysis are in `deployment/dependency-disposition.json`; no waiver or automatic approval is applied. Build setuptools84.1.0 is separate. Unknown license metadata/provenance must be resolved before distribution.
4. Identical final source, reproducible wheel/sdist, full installed-package and clean sdist tests, benign smoke and malformed-input tests. Intermediate dev wheels do not satisfy this gate.
5. Full54-file regression on the final installed wheel and approved patched runtime, compared per case and acceptance gate with RC9. A blocked launcher is an infrastructure blocker, not a packer `unsupported` result. No result may be borrowed from another code/runtime snapshot.
6. Target-platform remote CI and operational sign-off, including installation/rollback rehearsal, quarantine retention, incident response, and dependency support ownership. Workflows are prepared locally; no remote run or publication is authorized in this task.

Primary runtime advisory: <https://ubuntu.com/security/CVE-2026-87766> and <https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx>.

## Install a reviewed candidate

On an approved disposable Linux x86_64 worker with CPython3.13, a patched unprivileged Bubblewrap>=0.12.0 and existing cgroup-v2 user manager:

1. Verify the wheel and all dependencies against the release manifest. Use a pre-reviewed offline wheelhouse; do not resolve a new dependency environment silently.
2. Create a new versioned environment. Keep previous environments immutable and separate from output quarantine.
3. Install the52-package lock, then the exact candidate wheel:

```sh
python3.13 -m venv /approved/versioned/environment
/approved/versioned/environment/bin/python -m pip install \
  --no-index --no-deps --require-hashes --find-links /approved/wheelhouse \
  -r requirements/release-validation-linux-py313.lock
/approved/versioned/environment/bin/python -m pip install \
  --no-index --no-deps /approved/1200km_unpacker-1.2.0rc10-py3-none-any.whl
/approved/versioned/environment/bin/python -m pip check
```

The build environment uses `requirements/build.txt` and is not the emulation runtime. Never execute a specimen, its installer, wheel or setup script to validate it.

Run the installed verifier outside the checkout, using `-I -B`, with the exact wheel/source snapshot. `--sandbox` additionally requires the patched launcher; absence must fail rather than skip. Run the complete per-case corpus only after runtime and worker acceptance. Remote CI's patched-launcher prerequisite deliberately fails closed on an old runner image.

## Resource profiles and cancellation

Use `unpacker-worker`, not direct `unpacker`, for unknown specimens. Emulation is explicitly opt-in. The reference is mounted only in a separate validator. No host-file fallback exists in virtual guest file I/O.

| Profile | Decode | Total job | Namespace watchdog | Transient service | Client | External supervisor recommendation |
|---|---:|---:|---:|---:|---:|---:|
| Standard |60s|90s|95s|110s|120s|135s|
| Extended |180s|210s|215s|230s|240s|255s|

The extended profile changes wall time only. Keep2GiB group memory, swap0,32 tasks, one CPU,32MiB exported output,4096 entries, input32MiB and existing instruction/event/exception budgets. Higher bounds require separate review and measurements. SIGTERM returns143; SIGINT returns130 where the supervisor receives them. Cgroup cleanup must be verified after any cancellation; SIGKILL cannot execute a handler, so the finite service RuntimeMax and external supervisor remain necessary.

Example, only after all gates are satisfied:

```sh
unpacker-worker sample.bin -o quarantine/unique-job \
  --timeout 180 --total-timeout 210 --max-total-output-mb 32 \
  --max-output-entries 4096 --allow-emulation
```

`--bubblewrap /approved/path/bwrap` selects an operator-installed immutable patched binary. It does not waive version/privilege checks, grant user namespaces, alter AppArmor, or establish approval of that installation.

## Result and evidence contract

The controller snapshots and hashes exact input bytes, bounds the exported evidence archive, rejects unsafe members and contradictory report paths/hashes, and independently validates artifacts in another networkless namespace. The analysis worker receives no original/reference file. Raw worker output is evidence, not a terminal command or trusted success claim. `worker-report.json` preserves the producer report; `report.json` is controller-validated. Neither unsigned JSON nor hashes protect against an operator with write access to the evidence directory; store evidence in access-controlled immutable case storage where required.

An accepted result requires consistent artifacts, successful independent validation and the required quality level without warnings.7/7 reconstruction gates on a still-partial result do not automatically promote it. Structural and vendor validation are weaker than known-answer comparison. The gates do not prove behavior, general devirtualization, malware safety or recovery of every hidden payload. Corpus54 contains only12 unique original programs.

Never automate acceptance from a detected packer name or legacy exit0. `unpacker-worker` forces strict acceptance; direct/sandbox callers must select `--require-accepted`. Record status, validation level, all gates, input/output hashes, tool/runtime/dependency provenance and cleanup status.

## Upgrade and rollback rehearsal

Prepare a new immutable environment and compare source/wheel/dependency manifests. Run package verification and approved regression jobs before switching any operator launcher. Preserve the previous environment and evidence. Actual switching is a deployment action requiring approval outside this task.

For the first production release there is no previously approved production version to roll back to. Historical RC4/RC9 candidates are research snapshots, not an approved emergency fallback. If acceptance fails, stop new submissions, cancel owned jobs, verify cleanup, retain evidence, and leave the service/analyst launcher disabled. A local wheel install/uninstall rehearsal demonstrates packaging reversibility only; it does not establish operational rollback of a deployed service.

## Incident handling and retention

Use an operator-owned quarantine directory with restricted access, nonexecutable artifacts and a documented TTL. Do not open recovered specimens in a native application or send case data to an LLM without explicit scoped authorization. If containment or evidence integrity is suspect, stop submissions, retain bounded evidence and tool hashes, terminate the owned worker and reimage the disposable environment. Do not weaken isolation to recover a failing sample.

## Remaining capability work

Use the per-case matrix and final report. Alienyze's traced CreateFileW defect now has a bounded virtual implementation and synthetic tests; improvement on its real fixture remains unverified until a safe runtime is available. JDPack's `ulib.dll` message is evidence of a loader barrier, not proof that a dummy module would be correct. SEH/debug/CLR/GDI/virtualization and password-dependent formats retain explicit partial/unsupported/timeout outcomes. Additional guest APIs require reference semantics and state-transition tests; no dummy-success API is permitted.
