# Unpacker

Unpacker detects packing signals, extracts supported static payloads and
reconstructs selected PE32 programs in bounded guest emulation. It produces
reports and validation evidence. Detection, extraction, reconstruction and
behavioral equivalence are different outcomes.

**Current version: 1.2.0rc12. Production acceptance is incomplete. Universal
packer support and a production malware service are not claimed.** Development
was stopped on 2026-10-28 at the owner's request to document, commit and push
the work. This source update does not publish a package or deploy a service.

## Documentation

* [Installation, CLI, Python API and AI usage](docs/USAGE.md)
* [Architecture and trust boundaries](docs/ARCHITECTURE.md)
* [Results, packer matrix, known issues and release gates](docs/CURRENT_STATUS.md)
* [Actual experimental VM workflow](docs/VM_WORKFLOW.md)
* [Production operations and rollback](docs/PRODUCTION_RELEASE.md)
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
This documentation commit has no new full regression/corpus receipt; frozen
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

The publish workflow is disabled while gates remain open. No release tag,
package publication, deployment, new provider request or runner registration
is part of this source update.
