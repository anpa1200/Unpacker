> Historical publication copy. Dated results are not current readiness. Private paths are redacted and relative links repaired; see [current status](../CURRENT_STATUS.md). Original local receipts remain preserved.

# Unpacker

Bounded extraction and reconstruction of packed executables for malware analysis.
Unpacker combines content-based detection, native decompression, static container
recovery and explicitly enabled PE32 emulation. Every artifact carries validation
facts and a status. Coverage is measured per fixture; universal unpacking and
behavioral equivalence are not established.

## Release preparation

The local `1.2.0rc4` candidate targets a bounded Linux analyst CLI. See the
[production and rollback guide](../PRODUCTION_RELEASE.md) and
[fixture support matrix](../SUPPORTED_MATRIX.json). Candidate preparation does not
mean a production deployment or a published release.

## Measured capabilities

The [RC4 recovery ledger](../RC4_RECOVERY_2026_10_24.md) records 492 tests and a new single-wheel 54-file run: 33 accepted, 8 partial, 7 failed, 3 timeout and 3 unsupported. All 33 RC2 accepted fixtures retain their original gates.

The latest evidence and limitations are in the [60-second decode ledger](../DECODE_DEADLINE_2026_10_22.md).
The [failure-repair ledger](../FAILURE_REPAIRS_2026_10_21.md) records the earlier repair pass.
The [PECompact IAT follow-up](../PECOMPACT_IAT_2026_10_22.md) records descriptor-rooted recovery, 288 tests and one newly accepted fixture.
The [AI/runtime repair ledger](../AI_RUNTIME_REPAIRS_2026_10_22.md) records report-driven diagnosis, VirtualProtect fixes, 361 tests and the latest 54-file result matrix.
The [guest runtime follow-up](../GUEST_RUNTIME_2026_10_22.md) records scoped API/SEH support, 273 tests and the then-remaining reconstruction failures.
The [PEtite follow-up](../PETITE_HANDOFF_2026_10_22.md) records the corrected loader boundary and remaining compressed-stream failure.
The [previous sequential ledger](../SEQUENTIAL_PACKER_RESULTS_2026_10_21.md)
is a historical snapshot. The acquired corpus contains 54 packed fixtures across
32 normalized source-family labels. Its 31 paired cases represent 12 distinct
original hashes, with limited diversity of programs and packer versions.

| Path | Implemented behavior | Evidence and limits |
|---|---|---|
| UPX | Supervised system `upx -t` and `upx -d` | 23 acquired fixtures; DOS/COFF/TOS outputs use vendor validation |
| gzip shell wrapper | Static bounded gzip decoding | Acquired gzexe fixture matches its entire original |
| ELF note container | Extract one bounded, uncompressed appended ELF identified by PT_NOTE metadata | Acquired ward fixture matches its entire original; compressed/other layouts unsupported |
| Ezuri | Static AES-CFB trailer recovery with bounded ELF validation | Acquired fixture matches its entire original; optional crypto dependency, no authenticity guarantee from CFB |
| Pakkero | Bounded UPX-carried ELF64 Unicode-offset/AES-GCM static profile | Real fixture authenticates but self-embeds and remains partial; synthetic compatible known-answer fixture only; no launcher execution |
| Enigma Virtual Box | Narrow retained PE32 core extraction | Paired core passes static gates; embedded filesystem and wrapper behavior remain partial |
| Unipacker PE32 | CPU emulation, explicit guest API model, detached PE reconstruction | Successful fixture-level recovery for several packers; unsupported APIs, CPU faults and deadlines remain visible |
| Qiling PE32+ | Optional rootfs-based emulation and memory snapshot | Runtime/rootfs unavailable in this validation; snapshots always partial; no proven devirtualization |

Detector labels route an analysis attempt; a label alone is not implemented
recovery support. MPRESS and the generic PE32 path use the emulator when explicitly
enabled. Themida and VMProtect do not have complete packer-specific recovery engines.

## Installation

Python 3.10+ is required. From a trusted checkout:

```bash
pip install -e .
```

Optional dependencies:

- System UPX for native UPX extraction.
- `pip install -e '.[unipacker]'` for PE32 emulation. The pinned backend uses an older
  Unicorn/setuptools dependency chain.
- `pip install -e '.[crypto]'` for Ezuri static decryption.
- `pip install -e '.[config]'` for explicit YAML configuration.
- `pip install -e '.[emulation]'` plus an appropriate Windows rootfs for Qiling.
  This is separate infrastructure and has not been validated here.
- Provider extras and setup for AI advice are described in
  [AI architecture](../AI_ARCHITECTURE.md).

## Analyze hostile files in isolation

On Linux, use the namespace sandbox. It fails closed if Bubblewrap isolation is
unavailable. Guest execution is disabled by default.

```bash
unpacker-sandbox /path/input.bin -o ./evidence --timeout 60 --total-timeout 90

# Explicitly enable PE32 CPU emulation inside the sandbox.
unpacker-sandbox /path/input.bin -o ./evidence --allow-emulation \
  --timeout 60 --total-timeout 90 --max-total-output-mb 32

# Validate against a separately acquired original, when available.
unpacker-sandbox /path/input.bin -o ./evidence --allow-emulation \
  --reference /path/original.bin --timeout 60 --total-timeout 90
```

The default decode deadline is 60 seconds per backend across the CLI, sandbox,
Python API and example configuration. The overall job deadline remains 300 seconds;
an explicit `--timeout` or configuration value overrides the default. A timeout
remains an unsuccessful result and does not bypass reconstruction validation.

The sandbox has no network, private home directory or inherited credentials. Inputs
and code are read-only. Output lives on a capacity-limited private tmpfs before a
bounded archive is validated and copied to the fresh evidence directory. CPU,
address-space, file-size and wall-clock budgets also apply. Namespaces share the
host kernel; use a dedicated analysis VM where your threat model requires it.

The direct CLI/Python API is a lower-level interface. Its process limits are not
an OS security sandbox. See [hardening boundaries](../HARDENING.md) and
[containment validation](../CONTAINMENT_RECONSTRUCTION_2026_10_21.md).

## Read the result

Reports include input/output hashes, detection evidence, per-layer lineage,
validation facts, warnings, budgets and the reason analysis stopped. Emulated
artifacts stop for analyst review; native/static extraction can continue through
further layers within the configured limits.

- `extracted`: accepted extraction under the recorded validation scope.
- `extracted_vendor_format`: native-tool validation for a supported non-PE/ELF output.
- `partial`: an artifact exists with declared uncertainty, failed acceptance gates
  or an approximation. A partial core can pass all static original comparisons.
- `unsupported`, `failed`, `timeout`: the requested recovery was not established.

PE comparisons check executable bytes, entry RVA and mapping, imports, loader-ready
IAT values, a complete import-descriptor table and machine type. ELF paired cases
use whole-file SHA-256 equality. Structural parsing, lower entropy or a smaller
file alone never establish complete recovery. Paired originals are validation
inputs and are not used to synthesize reconstructed bytes.

The PE32 model uses an explicit single-thread Windows/ANSI profile. Guest paths
are never opened on the host. Unknown APIs stop execution. CRT callbacks run on the
guest CPU with bounded tables/nesting; they are not silently skipped. Import repair
operates on detached bytes, so rejecting a premature candidate does not alter the
running guest. Some recovery paths infer header layout from retained input metadata;
these remain partial even when original static gates pass.

The follow-up [loader and CRT repair ledger](../RESUMED_DEVELOPMENT_2026_10_21.md)
records corroborated recovery of zeroed import names, PE32 loader-list metadata,
legacy CRT startup/allocation/string models and bounded timeout CPU diagnostics.
CRT exit callbacks can be registered; exit-callback dispatch remains unsupported.
These are measured reconstruction improvements, not a claim of universal recovery.

## AI advisor

`unpacker-ai` accepts curated metadata JSON and returns evidence-linked advice via
OpenAI, Claude or Gemini adapters. It does not execute samples, change extraction
code or grant the LLM authority over the emulator. Review the exact outgoing payload
and use the explicit provider configuration described in
[AI architecture and setup](../AI_ARCHITECTURE.md).

It can now collect bounded, allowlisted run evidence and propose diagnostics for
failed import gates, decoder input, guest API gaps, timeouts and incomplete recovery:

```bash
unpacker-ai /path/to/run/report.json --from-report --preview
unpacker-ai /path/to/run/report.json --from-report --provider openai \
  --env-file /path/to/authorized.env
```

Preview makes no request and loads no credentials. An ordinary invocation sends
only the previewed metadata; raw reports and specimens remain local. Suggestions
must cite matching evidence and cannot run a backend or change acceptance gates.

## Configuration and extension

The direct CLI accepts explicit schema-validated YAML configuration. Unsupported
or misspelled settings fail instead of silently enabling behavior.

Adapters implement `BaseUnpacker` and can be registered through
`register_unpacker`. Detectors use content only; filenames do not select a packer.
The bounded JSON signature loader accepts an explicitly supplied signatures directory
through the Python detector API. No signature database is bundled. Standalone
arbitrary IAT discovery/rebuilding is still unimplemented and requests to enable it
are rejected; retained tables and observed-import recovery are separate capabilities.

## Development

```bash
pip install -e '.[dev]'
python -m pytest -q
python -m pip wheel --no-deps --no-build-isolation .
```

Unit tests use benign generated memory/metadata fixtures. Acquired specimens are
kept outside the repository and exercised only in the isolated evidence workflow.
New packer support needs malformed-input tests and known-original acceptance evidence,
not just another recognized name.

[Repository](https://github.com/anpa1200/Unpacker) · [MIT license](../../LICENSE)
