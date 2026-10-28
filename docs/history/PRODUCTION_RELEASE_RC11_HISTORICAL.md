> Historical publication copy. Dated results are not current readiness. Private paths are redacted and relative links repaired; see [current status](../CURRENT_STATUS.md). Original local receipts remain preserved.

# RC11 release gates and operations

This document describes candidate1.2.0rc11. Final artifact hashes, source inventory and actual verification receipts are external in the release manifest, avoiding circular self-hashes. Historical reports remain historical.

## Decision and supported scope

Production approval is pending. The target is an internal single-analyst CLI on a dedicated disposable Linux x86_64 worker with CPython3.12/3.13, cgroup v2, a maintained namespace launcher and no worker credentials/network. The package's>=3.10 metadata does not certify untested targets. A public multi-tenant service requires additional architecture and review.

Release requirements:

1. Approved disposable worker and patched Bubblewrap>=0.12.0. The current host's0.9.0-1ubuntu0.3 is blocked: its changelog removes CVE-2026-87766's fix and the verified official security index offers that revision. No vulnerable fallback exists. New task-local0.12.0 builds have0755, no task RPATH and reproducible bytes; root-owned placement and namespace policy acceptance have not been applied.
2. Actual production user-service namespace success plus benign network/nested-userns/readonly/credential denial, resource and cancellation acceptance. The previous corrected launcher received RTM_NEWADDR EPERM in the service; AppArmor attribution remains unconfirmed without administrator audit. Audit approval is pending; no denial bypass or host policy change is authorized here.
3. Identical final source/wheel/dependencies, full source and clean installed wheel/sdist tests, deterministic packaging, malformed input and independent report validation. Raw backend sdist timestamps require the documented canonicalization procedure; no raw reproducibility claim replaces evidence.
4. One full54-fixture run on the exact final installed candidate and approved runtime, compared case-by-case with RC9. No RC11 corpus result exists yet. Infrastructure failure must not be relabelled packer `unsupported`.
5. Target CI execution and operational install/upgrade/rollback/retention acceptance. Workflow preparation is not a remote CI result; no source push/publication is authorized.

Runtime advisory: <https://ubuntu.com/security/CVE-2026-87766>. New runtime builds and version gates reduce known exposure; they do not prove hostile-worker safety or absence of unknown vulnerabilities.

## Maintained emulator dependency and supply chain

The release supplies `unicorn-unipacker==1.0.3b7+unpacker.1` as a distinct owned build compatible with Unipacker1.0.8's public-version requirement. It is not represented as a public upstream release. The core is rebuilt from source matching tag1.0.3b7/c5c5b438490e50c3a96b35bfd4b35c2f06ff8144. The build-only MutableMapping import patch, deterministic object order, compiler/link flags and source/wheel hashes are recorded. Core C semantics are unchanged; the new binary still requires full regression/corpus acceptance.

The binding uses standard-library resource lookup and verifies the packaged native inode before dlopen; missing, changed, growing or symlinked cores fail closed. It does not search environment/system locations. Deprecated distutils/pkg_resources runtime imports are removed; setuptools84.1.0 is supported and no old-setuptools advisory waiver is used.

`deployment/owned-dependencies.json` binds the local version to wheel/native/source hashes and the public upstream identity. The advisory checker requires that provenance and wheel bytes before querying only the public name/base version. All upstream advisories remain active; mapping is not a security exemption or a comprehensive native-code audit.

Component license/notice materials and corresponding build inputs accompany the dependency. Source-only materials omit upstream sample/regression executables not needed by the library target. GPL-based native core, compatible component licenses, Unipacker's own notices and this project's MIT license are distinct. Inventory and source provision do not claim owner/legal approval or cover every future redistribution model. Project wheel, optional dependency bundle and worker image have different contents.

## Offline install

On an approved worker, verify the external manifest and use the matching hashed Linux-py312 or Linux-py313 validation lock. The wheelhouse must contain the exact owned build and reviewed public wheels. Use a new versioned environment; never install packaging content supplied by a specimen.

```sh
python3.13 -m venv /approved/versioned/environment
/approved/versioned/environment/bin/python -m pip install \
  --no-index --no-deps --require-hashes --find-links /approved/wheelhouse \
  -r requirements/release-validation-linux-py313.lock
/approved/versioned/environment/bin/python -m pip install \
  --no-index --no-deps /approved/1200km_unpacker-1.2.0rc11-py3-none-any.whl
/approved/versioned/environment/bin/python -m pip check
```

The build environment is separate. Exact linkage/toolchain provenance matters: changing compiler/native core/dependency bytes requires a new inventory and affected regression acceptance, not silently updating hashes.

## Validation and CI

Run `scripts/verify_installed_release.py` using the installed environment's Python `-I -B`, outside the checkout. It verifies wheel/source/installed byte identity, complete regressions with zero skips, all entry-point help/version, benign static extraction/reference checks, offline AI preview and malformed-input behavior.

On the approved boundary, add `--sandbox --production-worker --bubblewrap /approved/immutable/bwrap`. This explicitly tests cgroup-supervised benign extraction in60/180-second profiles, independent reference acceptance and collection of the owned service. Namespace-only testing without `--production-worker` does not establish the outer job boundary. These protected checks remain unexecuted until approval.

The prepared workflow requires an operator-provided disposable `unpacker-isolated-ci` runner, preinstalled interpreters and a readonly reviewed wheelhouse. It does not change AppArmor/sysctl or install a vulnerable system launcher. Its execution on the exact source still requires authorized CI/source access. Unit tests do not execute corpus specimens, and private corpus files are not uploaded to GitHub.

## Limits and cancellation

|Profile|Decode|Total job|Namespace|Service|Client|External supervisor recommendation|
|---|---:|---:|---:|---:|---:|---:|
|Standard|60s|90s|95s|110s|120s|135s|
|Extended|180s|210s|215s|230s|240s|255s|

Keep2GiB group memory, swap0,32 tasks, one CPU,32MiB exported output,4096 entries,32MiB input and existing instruction/event/exception ceilings. Extended time changes wall time only. Sample bounds are separate from trusted compiler build bounds. SIGTERM/INT trigger finite owned-job cleanup; service RuntimeMax and external supervisor remain necessary for uncatchable SIGKILL. Verify collection after cancellation, including setsid descendants.

## Evidence and operator semantics

Input snapshots fix the bytes mounted into the analysis namespace. Export import is bounded and rejects unsafe paths; controller validates JSON schema relationships, actual artifact hashes and paths. Separate networkless validation receives reference data; the unknown analysis worker does not. Raw producer report/logs are evidence, not executable commands or trusted success claims. Partial stays partial unless all actual acceptance conditions are met.

Production `unpacker-worker` requires independent acceptance for exit0. Structural/vendor validation remains weaker than known-answer comparison. Hashes and unsigned JSON are byte-integrity evidence, not producer signatures, behavioral equivalence or malware safety. Operator-controlled case storage needs its own access/immutability/TTL policy.

## Upgrade, rollback and retention

Prepare a new immutable versioned runtime, verify manifest and affected tests before any launcher switch. Actual deployment/switching is not part of this preparation. Preserve the approved previous environment and quarantined evidence. For a first release with no approved predecessor, rollback means stop submissions, collect owned jobs and leave the launcher disabled; RC4/RC9 research snapshots are not automatically approved fallbacks.

Use restricted quarantine, nonexecutable output files and documented retention. Never run recovered specimens natively or send private case data externally without scoped authorization. On suspected containment/integrity failure, stop new work, preserve evidence, terminate the owned worker and reimage the disposable boundary. Do not relax isolation to recover a failing specimen.

Known partial/unsupported capabilities remain documented. The real Alienyze CreateFileW change, JDPack loader barrier, timeout/SEH/CLR/GDI limits and packer-version coverage require fixture evidence; no new recovery count is claimed for RC11 before its full corpus. AI suggestions remain evidence-checked diagnostics with no execution/acceptance authority.
