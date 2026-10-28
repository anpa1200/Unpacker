# Change history

## 1.2.0rc13 — optional AI track alongside historical legacy

* Keep the historical non-AI 1.0.0 commit unchanged and expose it as a separate
  clearly labeled GitHub legacy snapshot; do not replace existing tags/releases.
* Keep extraction free of mandatory AI/cloud packages; provider extras and the
  `unpacker-ai` entry point remain optional.
* Make AI CLI preview offline by default. External metadata transmission now
  requires explicit `--send`; `--preview` remains supported.
* Add synthetic no-AI-import/network and no-credential-load preview regression
  contracts; provider behavior is tested through mocks, not live paid calls.
* Document separate environments, migration and rollback, prerelease limits and
  project-only artifact contents. No new corpus, VM acceptance or registry upload.

## RC12 source preservation and documentation — 2026-10-28

Preserve the verified RC12 source/tests that previously existed separately
from the RC4 repository tree. Add complete installation, CLI/API/AI, architecture,
fixture-matrix, actual VM and open-issue documentation. Redact private machine
paths from public copies while preserving original local receipts. Disable
publication pending release gates. No package, tag or deployment is created.

No new runtime feature, full test suite, corpus or provider request was completed
for this source/documentation update. Historical receipts apply to their frozen
artifacts, not a newly rebuilt distribution from this commit.

## Recorded RC12 milestone — 2026-10-27

* Finite, duplicate-free, depth-bounded JSON evidence contracts.
* Safe bounded tar import, implied-entry accounting and normalized path checks.
* Correct readonly upstream/Conda and Debian/Ubuntu package projection.
* 935 source and 935 installed tests plus 12 checks per Python 3.12/3.13.
* Exact 54-case corpus: 33 accepted, 9 partial, 4 timeout, 8 unsupported.
* Real namespace, resource-pressure, SIGTERM/watchdog and owned-cleanup controls.

Earlier work added bounded extraction/parsing, import reconstruction/provenance,
guest API/file/module/SEH models, layered deadlines, native binding verification,
explicit partial outcomes and constrained metadata-only AI advice. Dated reports
are historical; use [current status](docs/CURRENT_STATUS.md) for the final ledger.
