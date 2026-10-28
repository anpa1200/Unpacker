> Historical publication copy. Dated results are not current readiness. Private paths are redacted and relative links repaired; see [current status](../CURRENT_STATUS.md). Original local receipts remain preserved.

# Linux analyst CLI release candidate

## Current local RC4 checkpoint — October 24, 2026

RC4 v2 passed 492 source tests, 492 installed tests and eleven package checks.
One complete 54-file run on wheel SHA-256
`803017c9784b71a2f9801d737531b776a7eec4854c8900fa22f6a5154e9c90bb`
produced 33 accepted, 8 partial, 7 failed, 3 timeout and 3 unsupported results.
All 33 RC2 accepted fixtures retained their static acceptance gates. Pakkero
self-prefix extraction remains partial; Molebox still fails candidate IAT recovery.
See [RC4 ledger](../RC4_RECOVERY_2026_10_24.md) and [matrix](SUPPORTED_MATRIX_PRE_RC10_HISTORICAL.json).
Release is NO-GO pending dependency disposition, target CI and disposable-worker
acceptance. No publication or new private external LLM request occurred.

The following earlier preparation sections retain their historical measurements.


Status: local preparation of 1.2.0rc2. No push, publication, deployment, credential
creation or persistent host security change is performed by this workflow.

## Scope and evidence

The initial production target is a single-analyst Linux x86_64 CLI on CPython 3.13,
using Bubblewrap and explicit emulation opt-in. Python 3.10/3.12 remain compatibility
CI targets; their remote jobs must pass before advertising those targets as verified.
No public HTTP service, multi-tenant isolation, PE32+ reconstruction, Qiling rootfs,
general virtualization recovery or universal packer coverage is promised.

Read SUPPORTED_MATRIX.json for fixture-level results and provenance. The old corpus
contains 54 files, 31 original pairs and 12 unique originals; repeated UPX variants
limit its representativeness. A label and a passing unit suite are not proof that
all versions or behaviors of a packer can be recovered. Original programs are used
only for comparison, never to synthesize output. Structural-only, vendor-validated,
known-answer, partial and unrecovered results retain different meanings.

## Build and installed-wheel acceptance

Use an explicit build environment with requirements/build.txt. The observed
requirements/release-linux-py313.txt constrains 52 installed distributions for the
current target; it is not a hash-locked wheelhouse or a vulnerability assessment.
Setuptools supplies the wheel builder; no separate wheel distribution is required.

1. Build with `python -m build --no-isolation` in a reviewed source snapshot.
2. Install that wheel and declared test extras in a fresh virtual environment.
3. Run `python -I -B scripts/verify_installed_release.py --wheel /absolute/file.whl
   --source-root /absolute/reviewed/source --output /new/evidence --sandbox`.
4. Require at least 448 executed regressions, zero skips/errors/failures, byte equality
   between installed Python files and the wheel/source, all three CLI help/version
   checks, malformed-input failure, exact benign gzip/ELF recovery, offline AI preview
   and a real Bubblewrap benign extraction. Tests run in a copied suite without src
   or checkout pyproject; the actual pytest import origin is recorded.
5. In the private analysis environment, run the paired corpus through the installed
   sandbox package with 60-second decode / 75-second job / 32 MiB artifact limits.
   Reconcile every row with the recorded baseline; retain failed attempts/timeouts.

The public CI uses benign generated fixtures only. Private specimens, credentials,
proof archives and live provider calls must never be added to public PR CI.
Manual workflow dispatch validates only by default. Publishing requires a matching
version tag and an explicit release/publish selection after validation. The pypi
GitHub environment must have operator-approved protection and Trusted Publisher
settings; a YAML environment name does not prove those settings exist.

## Worker configuration requiring review

`deployment/worker-profile.example.json` is a proposal, not applied configuration.
It specifies job-wide memory, CPU and PID controls, separate from per-process
RLIMITs. Review it in a dedicated disposable worker environment, then test concurrent
jobs, memory/PID pressure, SIGTERM cancellation, crash cleanup and namespace denial.
Do not change sysctl/AppArmor, grant root or weaken isolation to make a test pass.
If Bubblewrap cannot create its boundary, stop; no host fallback is permitted.

A Python venv supplies packages but not a complete standard library; the sandbox
binds the base Python library and the selected package tree read-only. For deployment
use a minimal dedicated runtime, never a developer environment with unrelated secrets.
Bubblewrap shares the kernel; it is a component of the isolation policy.

## Results, operation and AI

Preserve report.json and invocation/process records. Monitor status, backend,
validation level, duration, timeout/resource-limit counts, worker crashes and storage
use. Treat sample content and raw logs as quarantined evidence, not public metrics.
Set a retention TTL and capacity policy before operation. Exported artifacts are
non-executable regular files and must not be launched on the analyst host.

CLI exit 0 includes extracted, extracted_vendor_format, extracted_unverified,
extracted_with_residual_evidence and no_packing_evidence. It does not mean universally
complete recovery. Inspect status, artifact_kind, validation_status and warnings.
Partial, unsupported, timeout and failure remain unsuccessful recovery outcomes.

AI is optional and separate from the specimen worker. Preview is offline and needs
no key. Production credentials must be provisioned separately by the operator and
must never be mounted into the worker. Define allowed metadata, retention and request/
cost budgets. Responses remain bounded advisory data; no generated action changes
validation or executes a backend. The October 22 single JSON approval grants no
permission for additional private metadata transmission. No new live AI call is
part of release preparation.

## Release and rollback

Before a release: review the diff, record a clean commit/tag and source manifest,
verify dependency licenses/advisories and a hash-locked artifact source, verify target
CI, installed-package and worker acceptance, and review the support matrix. Sign off
only the exact wheel/sdist hashes that passed. Publication is a separate authorized
action. Do not rebuild between approval and publication.

Keep the previous reviewed wheel and its manifest in an immutable local artifact
store. Deploy candidates by creating a new environment, then switch the operator's
launcher to the accepted version. Roll back by selecting the previous environment
or reinstalling the retained wheel with `--no-index --no-deps`; never resolve fresh
dependencies as part of an emergency rollback. Retain evidence and stop new jobs
while changing worker versions. Runtime environments are recreated, not moved.

## Primary references

- https://docs.python.org/3/library/venv.html
- https://docs.pytest.org/en/stable/explanation/goodpractices.html
- https://github.com/containers/bubblewrap#sandbox-security
- https://docs.kernel.org/admin-guide/cgroup-v2.html
- https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/

## Dependency security blocker observed during preparation

The downloaded Linux/CPython 3.13 validation wheelhouse has 52 wheels with a hash
lock in requirements/release-validation-linux-py313.lock. Local validation from
that wheelhouse is separate from the inherited development environment. The lock
is identity/reproducibility evidence; it does not mean those versions are secure.

The public PyPI version metadata reports active advisories for the observed AnyIO,
Capstone, certifi, cryptography, pyasn1, Pygments, setuptools and urllib3 versions.
Duplicate GHSA/PYSEC/CVE identifiers are aliases, not independent findings. Actual
reachability/exploitability in this application has not been established.

The release CI advisory gate intentionally fails for this dependency baseline.
There is no automatic exception or silent advisory suppression. A dependency
upgrade/disposition review is required before publication. In particular, the
current legacy emulator packaging requires setuptools<81, while the registry
reports fixes in 83.0.0/84.1.0. Replacing this dependency chain needs compatibility
work and a repeated reconstruction/containment acceptance run; raising the bound
blindly or vendoring vulnerable code under another name is not a remedy.

### Primary-source triage caveat

Registry flags are not eight confirmed exploitable vulnerabilities in Unpacker.
The setuptools GHSA-h35f-9h28-mq5c describes macOS filename normalization during
sdist creation; GHSA-xmj3-9gf7-h52w concerns Windows legacy wheel installation.
Neither behavior is the declared Linux-only worker path. The Capstone maintainer
advisory GHSA-289w-cm54-fgrm describes a 6.0 Alpha reduced-X86 build, while PyPI
flags the observed 5.0.7 package. Build/version applicability needs reconciliation.
These distinctions are recorded for review; no unreviewed waiver is inserted into
the gate. A clean registry scan alone would also not certify the old emulator.

Primary evidence:
- https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c
- https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w
- https://github.com/capstone-engine/capstone/security/advisories/GHSA-289w-cm54-fgrm

## Historical October 24 remaining-case follow-up

All 21 partial/unrecovered fixtures were retried with the installed RC2 pilot.
The result remains 7 partial, 7 failed, 3 timeout and 4 unsupported. All 33
previously accepted fixtures retained their result after correcting a test-harness
file-size ceiling. The consolidated matrix has two exact runtime source cohorts:
20 problem cases used the v3 pilot; VMProtect and 33 accepted cases used v4.
This is not one full-corpus run of the final wheel. Original failures are retained.

The pilot adds an explicit `--guest-yesno-answer {yes,no}` policy (default no),
stateful virtual screen DC queries, fixed guest theme colors, bounded C-drive
GetFullPathNameA, and ASCII-only CharUpperBuffA. No host UI or path access occurs.
Selecting Yes leaves dialog approximations visible; it does not promote partial
recovery. Unsupported paths, NLS, GDI objects and drawing still fail explicitly.

Installed-wheel verification passed 448 tests and all eleven checks, including
offline AI preview and real Bubblewrap benign extraction. See SUPPORTED_MATRIX.json
and the private evidence archive for per-case limits and provenance. No additional
private external model request was made. Release remains blocked by dependency
disposition, unexecuted remote CI and dedicated worker acceptance.

## Unified final-wheel corpus verification

One subsequent complete 54-fixture run used the exact final wheel SHA-256 196a07679eca908641825441c7122dcad4f9c851dcaaa70dd25da5c4d8126041. All statuses, validation levels and PE acceptance gates match the preceding matrix: 30 extracted, 3 extracted_vendor_format, 7 partial, 7 failed, 3 timeout, 4 unsupported. No prior rows were reused. Runtime and dependency bytes were checked before and after the run. The 448-test verification belongs to this exact wheel/runtime; tests were not unnecessarily repeated. SUPPORTED_MATRIX.json now records this single source snapshot. Dependency disposition, remote CI and dedicated worker acceptance remain release blockers; this result does not authorize publication.
