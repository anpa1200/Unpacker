# Production gates and operations

**Current decision: NO-GO for broad production activation.** Source preservation
and GitHub prereleases do not publish to a package registry, deploy a worker or waive the open
[gate ledger](CURRENT_STATUS.md#release-gates). Target: internal single-analyst
Linux x86_64 CLI, CPython 3.12/3.13, disposable outer worker and independently
validated output. A public multi-tenant malware service is outside verified scope.

The current optional-AI RC13 and historical non-AI snapshot are GitHub
prereleases, not production approvals. See [parallel releases](RELEASE_TRACKS.md).
Automated PyPI publication remains disabled; manual GitHub project-artifact
publication does not waive these gates.

## Actual state

The frozen RC12 installed package and local namespace/cgroup environment passed
its recorded tests and 54-case corpus. The root-owned patched Bubblewrap 0.12.0
launcher and two scoped enforcing AppArmor profiles were installed with separate
approval and verified benign controls; earlier RTM_NEWADDR denials are historical.
The new offline VM passed only a benign core static test. Its host still reports
GDS Vulnerable, so unknown samples remain blocked. Full guest runtime/reset/corpus,
Windows resource rights, protected CI and operational acceptance remain open.

## Installation and dependency integrity

Use [the offline install procedure](USAGE.md#installation), a fresh versioned
environment, exact hashed locks, approved wheelhouse and external artifact
manifest. Native build `unicorn-unipacker==1.0.3b7+unpacker.1` is distinct from a
public upstream release. Its traced source commit is
`c5c5b438490e50c3a96b35bfd4b35c2f06ff8144`; wheel/native/source hashes are bound in
`deployment/owned-dependencies.json`. The binding verifies its bundled native
inode before dlopen and rejects missing, symlinked, changed or growing cores;
no environment/system-library search is an accepted fallback.

Do not substitute a native library or silently update lock hashes. Corresponding
source, component notices and applicable rights must accompany any dependency
redistribution. Project Git does not include native wheels, source-offer archives,
Windows DLLs, corpus files or VM disks. The current public tree is not a complete
standalone offline release bundle. PyPI zero findings are not native/OS security
clearance. The advisory checker maps a verified owned build to its public upstream
identity without dropping upstream findings or transmitting private build content.

Bubblewrap's code-level floor is >=0.12.0. The advisory link is retained in
`runtime_gate.py`; per-target distro/backport and binary identity still require
review. Do not use the previously rejected vulnerable system launcher or relax
network/capability policy to make a sample pass. Package installation never
silently applies host AppArmor, sysctl, setuid or capability changes.

## Deadline profiles

|Profile|Decode|Total|Namespace watchdog|Service|Client|Outer recommendation|
|---|---:|---:|---:|---:|---:|---:|
|Standard|60s|90s|95s|110s|120s|135s|
|Extended|180s|210s|215s|230s|240s|255s|

Keep group memory <=2 GiB, swap 0, tasks <=32, one-CPU quota and finite watchdogs.
The recommended job uses 32-MiB exported output, 4096 entries and 32-MiB input.
Keep instruction/event/exception ceilings separate from wall time. Existing
process supervision handles SIGTERM/INT and stops the exact owned service;
service/external watchdogs remain necessary for uncatchable SIGKILL. Verify
setsid descendants and late writes are gone, not just the parent PID.

The experimental VM has a different trusted-boot envelope: 4-GiB guest memory,
6-GiB host cap, 64 tasks, one-CPU quota and 180-second lifetime. Its per-file disk
limit is not an aggregate VM quota and is not the production specimen profile.

## Evidence and safe operator semantics

Use `unpacker-worker` on an accepted worker; it requires independent accepted
recovery for exit 0. Direct/namespace CLIs need `--require-accepted` in automation.
Archive import rejects unsafe/duplicate paths and budgets implied directories;
strict JSON rejects duplicate keys, nonfinite/overflowed values and excess depth.
Input snapshots fix the bytes under analysis. The analysis cannot see the known
original; a separate jailed validator checks artifacts and comparison gates.
A producer report, signature or LLM recommendation cannot grant acceptance.
Structural/vendor checks are weaker than known-answer comparison, and all are
weaker than behavioral equivalence. Partial remains partial when warnings or
unimplemented wrapper behavior persist.

Keep report, integrity, invocation, tool/runtime hashes and cleanup receipts in
restricted nonexecutable case storage. Never treat recovered artifacts as safe.
Do not send private case metadata externally without applicable authorization.

## Verification and CI

On an accepted target, `scripts/verify_installed_release.py` checks installed
module/wheel/source identity, complete regressions with zero skips, entry-point
help/version, benign extraction/reference, offline AI preview and malformed input.
The optional `--sandbox --production-worker --bubblewrap /approved/bwrap` adds
real cgroup-supervised benign 60/180 profiles, independent acceptance and cleanup.
A different target or dependency/native/resource bytes requires fresh acceptance.

The checked-in tests workflow is manual and private-runner gated. It is a proposal
requiring an already approved disposable runner, protected environment, readonly
wheelhouse and interpreters. No persistent runner or protection policy is created
by Git push. A public self-hosted specimen runner is not approved. Do not infer
successful remote CI from local receipts or an old unrelated Actions run.
The publisher is disabled pending gates; no release/tag event publishes packages.

## Upgrade and rollback

1. Prepare a new immutable versioned environment; verify approved manifests and
   affected package, containment and corpus acceptance before switching launchers.
2. Preserve the last accepted environment and evidence. A research RC4/RC9/RC12
   snapshot is not automatically a production rollback target.
3. Stop new submissions on integrity/containment failure; stop and collect only
   owned jobs. Preserve quarantined evidence and reimage the disposable worker.
4. If an accepted predecessor exists, restore its approved launcher/environment
   and run its benign acceptance before resuming. Otherwise leave submissions
   disabled. Git reset alone does not roll back dependencies, profiles or a VM.

The local project-package RC11->RC12->RC11 rehearsal verified module bytes; whole
production-OS/worker rollback and activation were not performed.

## Storage, retention and owner decisions

Prepared values were 7-day retention, 8-GiB quarantine quota, 256-MiB case ceiling,
0700 case access, preserved legal holds and automatic deletion disabled. They
are proposals, not applied production policy. The owner must select capacity,
access, retention/backup/incident responsibilities and accepted CI policy.
Do not silently delete evidence or turn a workstation into an exposed service.

For VM details and exact uncompleted steps see [VM workflow](VM_WORKFLOW.md).
For every nonaccepted family and the complete corpus see [current status](CURRENT_STATUS.md).
