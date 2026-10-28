# Published release receipts and deployment status

Status: **2026-10-28**. Two project-only GitHub prereleases are published,
non-draft and not marked Latest. This follow-up changes documentation only;
existing tags/assets remain immutable. No application version or runtime code
changes, new package release or asset replacement is made by this docs commit.

## Immutable release targets

|Track|Tag|Source commit|
|---|---|---|
|Historical non-AI|[v1.0.0-legacy](https://github.com/anpa1200/Unpacker/releases/tag/v1.0.0-legacy)|`78c0e01718a07e297268b6bce7d9287243463ea1`|
|Core + optional AI|[v1.2.0rc13](https://github.com/anpa1200/Unpacker/releases/tag/v1.2.0rc13)|`fc2e23a1d1bc845f6db7f2335b1f77c31ec52afc`|

The legacy runtime/tests/package metadata remain identical to original commit
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. Its preservation commit changes only
automatic-workflow safety and adds a release note. It is historical software,
not a newly hardened stable fallback. The modern deterministic core has no
mandatory cloud dependency; optional AI defaults to offline preview and needs
explicit `--send` for a separately authorized metadata request.

## Verified checks

* Exact installed RC13 wheel: **939 tests, zero skips, 12 verification steps**
  on Linux x86_64 / CPython 3.12.
* After publication: reinstall the downloaded RC13 wheel and run **99 focused
  AI/dual-track tests**, all passing in 3.97 seconds. Providers are fake/mocked;
  no paid/live request or stored user credential is used.
* Downloaded legacy wheel: separate minimal environment, original CLI completes
  generated non-executable ELF metadata, all 24 installed modules match the
  wheel, no AI/cloud packages/imports or socket connections. This is a CLI
  compatibility check, not accepted specimen reconstruction.
* Modern core-only environment: exact original-byte recovery of a generated
  non-executable gzip/ELF fixture without AI dependencies/imports/network.
* Both clean sdists rebuild into byte-identical reviewed wheels. Sdist owner/
  timestamp metadata was canonicalized; file payloads were preserved.
* All **10 published asset downloads** exactly match reviewed local bytes and
  server SHA256 digests. Source/wheel payloads match their tag commits.

These checks do not replace protected target CI, full VM worker acceptance or
a new corpus run. The historical RC12 corpus remains 33 accepted / 9 partial /
4 timeout / 8 unsupported across 54 fixtures and 12 unique reference originals.

## Artifact SHA256

|Artifact|SHA256|
|---|---|
|Legacy 1.0.0 wheel|`20fd6d77b1398ab73dabd080e3ccd709a729123289be2af79330186f6eb6af22`|
|Legacy 1.0.0 sdist|`cac9a783ffa94e2aa89482fb268f51c53042301fb9fdae0dcc920d8b297862a6`|
|RC13 wheel|`794c732e67e309f291fd7c792aee3e5efbfd7a048f7cc76619f5c3f9c80429c7`|
|RC13 sdist|`399d799d1a7f2d5792e5251636e923fa3619fc0017dc5c6fe281c689cc132c64`|

Verify all five files per release using its SHA256SUMS. Full package identities
and scope are in release-manifest.json and validation-summary.json. No secrets,
Windows/native dependency binaries, specimens, private machine evidence,
wheelhouse caches or VM images are assets.

## What is deployed, and what is not

**Completed distribution target:** the two GitHub release pages and their
reviewed downloadable CLI artifacts. This is package delivery, not activation
of a running analyst service or an approved hostile-file worker.

Repository inspection found no network service, Docker/Compose/Kubernetes or
host install/activate workflow. `scripts/run_unpacker.py` is a CLI wrapper.
`deployment/worker-profile.example.json` is a review template, not an installer;
its RC12 target label is historical and does not assert RC13 VM acceptance.
The manual private-runner workflow is CI, not a configured deployment target.
The registry publisher intentionally fails closed and is not invoked as a
substitute for deployment. No PyPI registry publication is authorized here.

A separate runtime installation needs **an existing target host and versioned
installation directory** for the two environments. No destination was specified
in the follow-up request. No service is started, port exposed, new account/
credential/runner registered or host-security setting changed without that scope.
Use [parallel install/rollback instructions](RELEASE_TRACKS.md) once the target
is selected; preserve legacy and current environments separately.

Unknown/malicious samples remain out of scope while host GDS is unresolved.
Full guest runtime/reset/containment/corpus, native/Windows-resource rights,
protected CI and operational storage/retention acceptance remain open. A CLI
installation alone would not close these production gates.
