# Unpacker

Unpacker detects packing signals, extracts supported static payloads and
reconstructs selected PE32 programs in bounded guest emulation. It produces
reports and validation evidence. Detection, extraction, reconstruction and
behavioral equivalence are different outcomes.

**Current version: 1.2.0rc13, AI-assisted prerelease. Production acceptance remains incomplete.**
The non-AI 1.0.0 source is preserved unchanged as a separate historical legacy
release; no old tag or release is replaced. Neither track is newly certified
for hostile production workloads. See [parallel release tracks](docs/RELEASE_TRACKS.md).

|Track|Version/tag|Cloud dependency|
|---|---|---|
|Historical legacy|1.0.0 / [`v1.0.0-legacy`](https://github.com/anpa1200/Unpacker/releases/tag/v1.0.0-legacy)|None; original source and CLI preserved|
|Current core + optional AI|1.2.0rc13 / [`v1.2.0rc13`](https://github.com/anpa1200/Unpacker/releases/tag/v1.2.0rc13)|None for extraction; selected AI extra is optional|

`unpacker` remains deterministic and does not invoke AI. `unpacker-ai` previews
allowlisted metadata offline by default. An intentional external request requires
`--send`; even an existing API key or `--env-file` does not turn preview into sending.
Use separate virtual environments to keep both versions installed in parallel.

## Documentation

* [Installation, CLI, Python API and AI usage](docs/USAGE.md)
* [Architecture and trust boundaries](docs/ARCHITECTURE.md)
* [Results, packer matrix, known issues and release gates](docs/CURRENT_STATUS.md)
* [Actual experimental VM workflow](docs/VM_WORKFLOW.md)
* [Production operations and rollback](docs/PRODUCTION_RELEASE.md)
* [Published releases and deployment destination](docs/RELEASE_STATUS.md)
* [AI contracts and provider architecture](docs/AI_ARCHITECTURE.md)
* [Machine-readable fixture matrix](docs/SUPPORTED_MATRIX.json)
* [Change history](CHANGELOG.md)

## Implemented capabilities

* PE/ELF format and architecture inspection, signatures, sections, entropy and
  heuristic signals; analyst backend hints are separate from detection.
* Native UPX decoding when a compatible vendor executable is installed;
  bounded static gzip/ELF-note and supported ezuri/pakkero extraction paths.
* Opt-in PE32 Unipacker/Unicorn emulation; bounded import/IAT reconstruction,
  write/handoff tracking and code/entry/import validation. Selected Win32,
  virtual self-file, CRT, module/export, protection and x86 exception models.
* Backend/job deadlines, aggregate byte/entry budgets, owned-process cleanup,
  strict JSON/tar evidence import and separately isolated artifact validation.
  The worker CLI adds a transient resource-limited cgroup.
* Optional OpenAI/Claude/Gemini diagnostic adapters with exact offline metadata
  preview. Advice cannot execute code, dispatch unpackers or approve recovery.

## Current release verification

The published RC13 wheel passed **939 installed tests plus 12 verification
steps on CPython 3.12**. A post-publication check reinstalled the downloaded
GitHub wheel and passed **99 focused AI/dual-track tests**; the downloaded
legacy wheel also passed its separate benign CLI check. All ten published
assets were downloaded and hash-verified. See [release receipts and deployment
status](docs/RELEASE_STATUS.md). These are local benign/mock checks, not a new
corpus, live-provider or production-worker acceptance run.

## Recorded verification

The final exact-wheel RC12 corpus run completed on **2026-10-27**:

|Outcome|Fixtures|
|---|---:|
|Accepted|33|
|Partial|9|
|Timeout|4|
|Unsupported|8|
|Failed|0|
|Total|54|

Accepted levels: **12 known-answer, 18 structural, 3 vendor**. The corpus has
**12 unique reference originals**, not 54 independent original programs. These
gates do not establish universal behavior, arbitrary packer-version support or
VMProtect devirtualization.

The frozen candidate recorded **935 source tests and 935 installed tests plus
12 verification checks on each CPython 3.12/3.13 environment**. A later real
Vagrant/QEMU/KVM VM passed one benign static extraction with exact original
bytes. Full runtime/corpus testing inside that VM was not completed.
The RC13 change does not include a new corpus/VM acceptance run; frozen
package results and publication-only changes are separated in current status.

## Benign developer quick start

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/unpacker --help
.venv/bin/unpacker /path/to/benign-packed-file -o /path/to/new-output \
  --json --report-file /path/to/new-report.json --require-accepted
```

This direct command does not provide an OS security sandbox. Production-target
installation uses reviewed offline wheels and hashed locks. The owned native
build `unicorn-unipacker==1.0.3b7+unpacker.1` is not available as that version on
public PyPI. Wheels, Windows resources, corpus files and VM images are not in Git.

On a separately approved disposable worker, the full job interface is:

```sh
unpacker-worker /cases/input.bin -o /cases/new-job \
  --bubblewrap /opt/unpacker-runtime/bwrap-0.12.0/bin/bwrap \
  --timeout 60 --total-timeout 90 \
  --max-total-output-mb 32 --max-output-entries 4096
```

Emulation requires `--allow-emulation`. Unknown/recovered files remain untrusted.
`--reference` is supplied only to the independent validator, not the analysis
namespace. Direct/namespace CLIs need `--require-accepted` for strict automation;
the worker enables it automatically. Partial and unsupported are not success.

## Remaining production gates

The validation host still reports **Gather Data Sampling: Vulnerable**. No
mitigation reboot has been performed; unknown samples remain blocked in its
experimental VM. Full guest runtime, reset, negative controls and exact corpus
acceptance remain open, as do Windows DLL/LDLL rights or a validated replacement,
protected CI and operational storage/retention acceptance.

Automated registry publication remains disabled. The two GitHub prereleases
contain reviewed project-only artifacts; no PyPI publication, deployment, live
provider call or persistent runner registration is part of this release.
