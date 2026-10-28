> Historical publication copy. Dated results are not current readiness. Private paths are redacted and relative links repaired; see [current status](../CURRENT_STATUS.md). Original local receipts remain preserved.

# Unpacker

Unpacker detects packed files, extracts supported static payloads, and recovers selected PE32 programs in bounded guest emulation. Recognizing a packer name does not establish successful recovery. Recovered artifacts remain untrusted.

## RC11 status

**1.2.0rc11 is a locally prepared release candidate. Production acceptance remains blocked on the approved worker boundary and final corpus verification.** No publication or deployment has occurred.

The release target is a dedicated disposable Linux x86_64 analyst worker, CPython3.12/3.13, cgroup v2 and patched unprivileged Bubblewrap>=0.12.0. Package metadata compatibility>=3.10 is broader than the verified production target. A multi-tenant web service and universal packer recovery are not claimed.

RC11 uses an explicitly versioned maintained `unicorn-unipacker1.0.3b7+unpacker.1` dependency: native core rebuilt from traced source; obsolete packaging imports removed; the bundled core is verified before loading. This owned build is supplied in the reviewed offline release materials, not fetched as a nonexistent public PyPI version. It requires the corresponding dependency wheel/lock and component source/notice materials.

## Installation and execution

See [production gates and operations](../PRODUCTION_RELEASE.md). Install the exact wheel and hashed dependencies from the reviewed offline wheelhouse in a fresh versioned environment. The public index alone cannot supply the owned dependency.

On an approved worker:

```sh
unpacker-worker specimen.bin -o quarantine/unique-job \
  --bubblewrap /opt/unpacker-runtime/bwrap-0.12.0/bin/bwrap \
  --timeout 60 --total-timeout 90 \
  --max-total-output-mb 32 --max-output-entries 4096
```

Emulation requires explicit `--allow-emulation`. `--reference original.bin` supplies paired acceptance data only to the separately isolated validator; the analysis namespace cannot see it. Production worker requires accepted recovery for exit0. `unpacker` is the direct developer/benign-fixture entry point, and `unpacker-sandbox` is namespace-only; they do not supply the full outer job boundary. Their legacy completion semantics require `--require-accepted` for strict automation.

## Results

- `known_answer_verified`: the provided original comparison gates passed; this does not prove every behavioral property.
- `structurally_valid`: format/import/entry mapping accepted without a known original; weaker than known-answer recovery.
- `vendor_validated`: supported vendor decoder accepted the payload; not proof of runtime behavior.
- `partial`, `unsupported`, `timeout`, `failed`, unverified/residual and `no_packing_evidence` are not accepted unpacking.

Retain report, integrity, invocation, tool hashes and cleanup evidence. Never promote a partial result merely because some or all reconstruction gates passed.

[SUPPORTED_MATRIX.json](../SUPPORTED_MATRIX.json) is the frozen **historical RC9 baseline**,54 fixtures from12 unique originals:33 accepted,8 partial,2 failed,4 timeout,7 unsupported. Accepted levels are12 known-answer,18 structural and3 vendor. Those results have not been transferred to RC11. They do not establish support for every packer version/configuration or general VMProtect devirtualization.

The AI CLI supports offline redacted previews and constrained diagnostic suggestions. Advice cannot execute generated code or promote acceptance. Private external-provider requests require applicable explicit authorization; no new live-provider test is included in this release preparation.

See the final external release manifest/report for exact artifacts and actual checks, and `docs/history/` for older snapshots. Component license declarations do not relicense third-party dependencies under this project's MIT license.
