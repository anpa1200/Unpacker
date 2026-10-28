> Historical publication copy. Dated results are not current readiness. Private paths are redacted and relative links repaired; see [current status](../CURRENT_STATUS.md). Original local receipts remain preserved.

# Unpacker

Unpacker is an analyst CLI for detecting packed files, extracting supported static payloads, and recovering selected PE32 programs in bounded guest emulation. A recognized packer name does not establish successful recovery. Outputs remain untrusted analysis artifacts.

## Release status

**1.2.0rc10 is a local release-preparation candidate, not an approved production release.** The current host's Bubblewrap0.9.0-1ubuntu0.3 is blocked for CVE-2026-87766. No publication or deployment has taken place. Final results and exact artifact hashes belong to the accompanying RC10 release manifest and report; historical reports are not current acceptance evidence.

The proposed supported deployment is Linux x86_64, CPython3.13, a dedicated disposable single-analyst worker, a patched unprivileged Bubblewrap>=0.12.0, and an existing cgroup-v2 user service manager. General multi-tenant service, native specimen execution and universal packer recovery are outside the validated scope. Python>=3.10 is package metadata compatibility; other interpreter/platform acceptance requires its own CI results.

## Installation and operation

Follow [production preparation and operational gates](../PRODUCTION_RELEASE.md) before running unknown inputs. Use the exact reviewed wheel and hashed Linux dependency lock in a fresh environment; do not install software supplied by a specimen.

```sh
unpacker-worker specimen.bin -o quarantine/job-001 \
  --timeout 60 --total-timeout 90 \
  --max-total-output-mb 32 --max-output-entries 4096
```

The worker requires its cgroup and a patched namespace launcher and exits nonzero when these are unavailable. Emulation is off unless `--allow-emulation` is supplied. `--reference original.bin` is available for paired validation: the analysis namespace cannot see this reference; a separate isolated validator does.

`unpacker` is the direct developer/benign-fixture entry point. `unpacker-sandbox` supplies namespace isolation without the complete outer job supervisor. These entry points are not substitutes for the production worker boundary.

## Understanding results

- `extracted` with `known_answer_verified`: verified against the provided reference gates. This is stronger than structural validation, but not proof of all behavioral equivalence.
- `extracted` with `structurally_valid`: validated format/import/entry mapping without a known original. It is not equivalent to exact original recovery.
- `extracted_vendor_format` with `vendor_validated`: the supported vendor decoder accepted the format; it does not prove runtime behavior.
- `partial`, `unsupported`, `timeout`, `failed`, `extracted_unverified`, residual evidence and `no_packing_evidence` are not accepted unpacking.

`unpacker-worker` requires independently accepted recovery for exit0. Legacy direct/sandbox completion semantics can return0 for a completed unverified/no-packing outcome; use `--require-accepted` for strict automation. Always retain `report.json`, `integrity.json`, invocation and cleanup evidence; exit status alone does not establish universal correctness.

## Evidence and support

[SUPPORTED_MATRIX.json](../SUPPORTED_MATRIX.json) records the frozen RC9 regression baseline, not an RC10 corpus result. It contains54 fixtures derived from12 unique reference originals, with33 accepted,8 partial,2 failed,4 timeout and7 unsupported. The accepted levels are12 known-answer,18 structural and3 vendor. This small corpus is not a claim about every version or configuration of a packer, and VMProtect outputs do not establish general devirtualization.

The AI CLI provides offline redacted previews and schema-constrained diagnostic advice. It has no authority to execute generated code or promote an unpacking result. External requests require explicit applicable approval; no live-provider test is part of RC10 validation.

Development and evidence history are retained under `docs/history/`. See [SECURITY.md](../../SECURITY.md), [CONTRIBUTING.md](../../CONTRIBUTING.md), and the production document for build, test, release and rollback requirements.
