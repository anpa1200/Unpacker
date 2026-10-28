# Installation and usage

## Execution modes

`unpacker` is for reviewed benign developer fixtures or use inside an accepted
outer boundary. Subprocess limits alone do not contain a hostile native parser.
`unpacker-sandbox` adds networkless Linux namespaces. `unpacker-worker` also
adds transient user-cgroup limits and exact owned-group cleanup. A disposable
VM is the intended outer hostile-worker boundary; Docker alone does not supply it.

Do not run unknown specimens on the GDS-vulnerable validation workstation or
inside its experimental VM. Examples for approved workers do not waive that gate.

## Installation

Verified target: Linux x86_64, CPython 3.12/3.13. Package metadata permits >=3.10,
which is broader than the verified target. Core checkout installation:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/unpacker --version
```

Core dependencies are pefile and pyelftools. For an offline exact environment,
provide reviewed distributions at the placeholder paths below:

```sh
python3.12 -m venv /opt/unpacker/releases/rc12
/opt/unpacker/releases/rc12/bin/python -m pip install \
  --no-index --no-deps --require-hashes --find-links /approved/wheelhouse \
  -r requirements/release-validation-linux-py312.lock
/opt/unpacker/releases/rc12/bin/python -m pip install \
  --no-index --no-deps /approved/1200km_unpacker-1.2.0rc12-py3-none-any.whl
/opt/unpacker/releases/rc12/bin/python -m pip check
```

Use the py313 lock with CPython 3.13. Verify the project wheel against the
approved external manifest. The checkout does not provide that wheelhouse.
The validation lock includes development/provider dependencies; it does not
configure every optional engine or grant rights to third-party resources.

PE emulation uses Unipacker 1.0.8 and the maintained, separately owned
`unicorn-unipacker==1.0.3b7+unpacker.1` build. Public PyPI alone cannot supply the
local version. Do not substitute a native library or edit hashes to bypass an
installation failure. See `deployment/owned-dependencies.json` and the component
source/notice requirements. Six Windows DLL/LDLL resources require a separate
rights decision. A licensed Windows rootfs is not bundled.

Source extras: `[dev]`, `[config]`, `[crypto]`, `[acquisition]`, `[emulation]`,
`[unipacker]`, `[ai]`, `[ai-openai]`, `[ai-claude]`, `[ai-gemini]`. Native UPX is
an external vendor executable, not installed by the project package.

## Direct CLI: benign data

```sh
unpacker /data/benign-wrapper.bin -o /data/new-output \
  --json --report-file /data/new-report.json \
  --timeout 60 --total-timeout 90 --require-accepted
```

Attempt directories and the explicit report filename must be new-run evidence.
The report file is exclusively created. `--packer upx` is an analyst hint,
recorded separately from detection. A paired reference can be checked:

```sh
unpacker /data/benign-wrapper.bin -o /data/reference-check \
  --packer gzexe --reference /data/known-original.bin --json --require-accepted
```

Direct defaults: 5 layers, 60-second backend decode, 300-second total deadline,
32-MiB single output, 128-MiB aggregate output and 4096 entries. These differ
from the recommended explicit worker profile. `--config config/config.yaml`
loads bounded implemented orchestrator settings; CLI values override them.
Historical detector/unpacker YAML sections are not all wired into dispatch.
Signature-DB loading and standalone general IAT rebuilding are not established
by scaffolding; integrated validated PE import reconstruction is separate.

## Approved worker

```sh
unpacker-worker /cases/input.bin -o /cases/unique-job \
  --bubblewrap /opt/unpacker-runtime/bwrap-0.12.0/bin/bwrap \
  --timeout 60 --total-timeout 90 \
  --max-total-output-mb 32 --max-output-entries 4096 \
  --reference /references/original.bin
```

The unknown-input namespace never receives the reference. The subsequent
independent validator receives it readonly. Producer JSON/tar remains untrusted
until controller schema, path, byte/hash and artifact checks pass.

Add `--allow-emulation` only inside an accepted boundary. Named-export guest
modeling is default; `--guest-module-profile core-strict` restricts it.
`--guest-yesno-answer yes|no` is explicit, default `no`; modeled interaction can
retain a partial result. Qiling's `--rootfs` requires a separately supplied
rootfs and is not a universally validated fallback.

Extended wall-clock profile:

```sh
unpacker-worker /cases/input.bin -o /cases/new-extended-job \
  --bubblewrap /opt/unpacker-runtime/bwrap-0.12.0/bin/bwrap \
  --timeout 180 --total-timeout 210 \
  --max-total-output-mb 32 --max-output-entries 4096 --allow-emulation
```

It does not raise instruction, event, exception, memory or output budgets.
A timeout changing to unsupported is not accepted recovery.

## Outcomes and exits

|Outcome|Interpretation|
|---|---|
|`known_answer_verified`|Implemented code/entry/import gates passed against the supplied original|
|`structurally_valid`|Structural acceptance without proof of original equivalence|
|`vendor_validated`|Supported vendor decoder accepted the output|
|`partial`|Incomplete/degraded result, even when comparison gates pass|
|`unsupported`|Explicit missing format, architecture, API or exception capability|
|`timeout`|Finite operation did not complete in time|
|`failed`, `backend_error`, `dependency_error`, `resource_limit`|No accepted reconstruction; inspect cause|
|`no_packing_evidence`, unverified or residual evidence|Observation/completion, not accepted unpacking|

Direct/namespace CLIs retain legacy completion exits; use `--require-accepted`.
The worker adds that condition. Input/configuration errors return 2; unsuccessful
recovery is nonzero. Handled SIGTERM/INT cancellation uses 143/130. Always
inspect cleanup and independent integrity receipts.

## Python API

For reviewed benign fixtures or inside an accepted boundary:

```python
from pathlib import Path
from unpacker.orchestrator import run

report = run(
    Path("benign-wrapper.bin"), Path("new-output"),
    timeout_seconds=60, total_timeout_seconds=90,
    max_total_output_size_mb=32, max_output_entries=4096,
    allow_emulation=False,
)
print(report.status, report.stop_reason)
```

Embedding does not create a cgroup/VM or confer production acceptance.

## Optional AI

Install the selected provider extra in a managed environment. Preview needs no
key and makes no network request:

```sh
unpacker-ai docs/ai-evidence-example.json --preview
unpacker-ai /cases/job/report.json --from-report --preview
```

After reviewing the exact payload and authorizing its external disclosure:

```sh
unpacker-ai /cases/job/report.json --from-report \
  --provider openai --model gpt-6.1-sol --env-file /secure/provider.env
```

The last command makes a real request. The code's OpenAI default model string
is `gpt-6.1-sol`; account availability/compatibility are separate. Use
`--model-from-env` for provider model settings. Claude/Gemini require their
selected provider key/model. Explicit dotenv is parsed without sourcing or
interpolation, never edited; no home-directory secret search occurs.

The collector sends bounded allowlisted metadata, not binaries, raw reports,
paths, sample hashes, logs or disassembly. Metadata may still be sensitive.
Advice is diagnostic, schema/evidence checked and unable to execute or approve
unpacking. See [AI architecture](AI_ARCHITECTURE.md).
