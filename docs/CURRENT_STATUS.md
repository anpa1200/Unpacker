# Current status and known issues

Status captured for source preservation on **2026-10-28**. Development/testing
was stopped at the owner's request. This document separates recorded results
from planned or unfinished capabilities. No universal or production-ready claim.

## Source and package lineage

The repository previously held RC4 working changes on base commit
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. This update preserves the later
verified RC12 application/runtime source and tests, plus public documentation.
Original working files and frozen RC4/RC12 evidence remain locally preserved.
Machine paths in public documentation/test literals are redacted; application
runtime bytes are compared with the frozen RC12 source before committing.

The recorded RC12 distribution was verified separately:

* Wheel SHA256: `5910774f9c0ea102db57f509c8d892484b212eca51331520180a605ac12a7273`.
* Sdist SHA256: `84e80ced5fba83a1f552bfa807a89a0b038f6a0225e529c6c1b0ff692fd0e374`.
* 935 source tests; 935 installed tests plus 12 verification checks on each
  CPython 3.12/3.13 environment. Optional-dependency skips do not satisfy the
  release gate. Clean wheel/sdist install and project upgrade/rollback were tested.
* Two raw wheels matched. Sdist reproducibility used explicit metadata-only
  canonicalization; raw backend sdist timestamps were not claimed identical.
* Full 54-case run: 2026-10-27 07:00:44–07:19:30 UTC, exact installed candidate,
  no historical-row reuse, no native specimen execution or private LLM requests.

Documentation, publication-path redaction and workflow changes alter source
publication/package metadata. These historical hashes and tests are not a new
wheel built from this commit or a fresh full-suite result on this commit.
No new build, expensive tests, provider call or specimen run was performed for
this source/documentation update.

## Corpus interpretation

**33 accepted, 9 partial, 4 timeout, 8 unsupported, 0 failed, 54 total.**
Accepted levels: **12 known-answer, 18 structural, 3 vendor**. There are
**12 unique reference originals**, not 54 independent original applications.
All 33 previous accepted results and their gates were preserved in the final run.
Input/reference identities and raw artifacts remain local; the public summary
omits them. Packer names/versions/configurations outside these fixtures are untested.

The PE gates are executable bytes, entry RVA, entry mapping, imports,
loader-ready IAT, import descriptors and machine. A gate pass is narrower than
behavioral equivalence. Partial remains partial even if all seven gates pass.
Structural/vendor acceptance is weaker than original comparison. This is not
VMProtect devirtualization or general handling of every protector.

## Per-family recorded results

|Family|Accepted|Partial|Timeout|Unsupported|
|---|---:|---:|---:|---:|
|ASPack|1|0|0|0|
|Alienyze|0|1|0|0|
|Amber|0|0|1|0|
|BeRoEXEPacker|1|0|0|0|
|EXpressor|0|1|0|0|
|Enigma Virtual Box|0|1|0|0|
|Eronana Packer|0|1|0|0|
|Exe32pack|0|1|0|0|
|FSG|0|1|0|0|
|JDPack|0|0|0|1|
|MEW|1|0|0|0|
|MPRESS|1|0|0|0|
|Molebox|0|0|1|0|
|NSPack|1|0|0|0|
|Neolite|0|1|0|0|
|PECompact|1|0|0|0|
|PEtite|0|1|0|0|
|Packman|1|0|0|0|
|RLPack|0|0|0|1|
|TELock|0|0|0|1|
|Themida|0|0|1|0|
|UPX|23|0|0|0|
|VMProtect|0|0|0|1|
|WinUpack|0|0|0|1|
|YZPack|0|0|1|0|
|Yoda-Crypter|0|0|0|1|
|Yoda-Protector|0|0|0|1|
|ezuri|1|0|0|0|
|gzexe|1|0|0|0|
|midgetpack|0|0|0|1|
|pakkero|0|1|0|0|
|ward|1|0|0|0|

UPX case variants are combined in this table; the JSON retains original family
labels. Counts describe fixtures, not an exhaustive supported-format catalog.

## Remaining recovery failures and limitations

* **Alienyze:** partial; executable bytes do not match the known original although
  entry/import gates pass. Improved dumping did not establish full reconstruction.
* **EXpressor, Eronana, Exe32pack, FSG, Neolite:** degraded emulation dumps remain
  partial despite passing original comparison gates; inspect retained repair
  warnings rather than promoting them by gate count.
* **Enigma Virtual Box:** original comparison gates pass, but embedded VFS and
  wrapper TLS behavior are not reconstructed; partial is intentional.
* **PEtite:** partial, no reconstructed imports and failing executable-byte/entry
  gates. This is not solved by a parsable file or a decoder message.
* **pakkero:** authenticated payload matches its carrier prefix; original
  application recovery is not established. Authentication alone is not success.
* **Amber, Molebox, Themida, YZPack:** finite emulation deadline reached. Additional
  time/loader progress did not produce accepted recovery. No proven universal
  loop-breaking or protector-model solution is claimed.
* **JDPack:** virtual CreateFileA path is outside the supported local self-file
  profile. It does not fall back to host files or network/device paths.
* **RLPack:** interrupt vector/encoding outside the bounded x86 exception model.
* **TELock:** `_CorExeMain` execution semantics/CLR handoff are not implemented.
* **WinUpack:** malformed nonempty input imports need a compatible custom loader.
* **Yoda-Crypter:** outstanding/altered exception registrations at handler return.
* **Yoda-Protector:** guest exception event budget exceeded.
* **midgetpack:** fixture is outside the backend's valid PE32 requirement.
* **VMProtect:** `GetSysColorBrush` execution semantics are not implemented in
  the tested path. Export recognition or a GDI handle is not devirtualization.

These are observed barriers. They do not establish a complete root cause for
all possible files bearing the same family name. Unknown semantics stay
unsupported instead of returning dummy success. No further repairs were made
after development was stopped.

## Boundary and VM evidence

The final local namespace/cgroup candidate recorded four benign positive
controls, 15 namespace negative controls on each interpreter, three small
resource-pressure controls and two actual SIGTERM/watchdog cancellation controls.
They observed capabilities, readonly mounts, hidden references/credentials,
network isolation, nested-userns denial, tmpfs quota and owned-unit collection.
Pressure limits were deliberately smaller than the production profile. None
proves absence of kernel/native exploits or target portability.

The later Vagrant/QEMU/KVM proof had 2 vCPUs, 4 GiB RAM, no NIC/shares/SSH and
passed one generated metadata-only gzip/ELF static recovery. It powered off and
was collected. Full emulator/provider/dependency suite, VM reset and 54-case
corpus were **not run inside that VM**. The 2026-10-28 full-runtime bundle attempt
stopped before boot at an overly broad executable-content exclusion matching
setuptools launchers; it contributes no passing runtime evidence.

## Release gates

|Gate|Current state|What remains|
|---|---|---|
|Application implementation and historical package tests|Recorded pass on frozen RC12|No new full run for this documentation commit|
|Exact installed 54-case local corpus|Recorded complete; 33 accepted|Not full coverage or VM acceptance|
|Approved local Bubblewrap/AppArmor + cgroup controls|Recorded benign/negative/control passes|Revalidate each distinct target; no portability claim|
|Dedicated VM|Benign core proof only|Full runtime, reset, storage/transport and hostile-worker acceptance|
|Host CPU GDS mitigation|Blocked: host reports Vulnerable|Separately approved maintenance boot and post-boot checks, or a suitable different host|
|Windows DLL/LDLL rights|Unresolved|Applicable resource rights or separately validated independent replacement|
|Source-only/BYOR dependency|Packaging/inert loader feasibility only|Owned provenance/locks, legitimate resources or independent model, installed/full-corpus acceptance|
|Dependency advisories|52 public versions checked on 2026-10-27; zero active PyPI findings|Current target native/OS/vendor review; no perpetual security clearance|
|Protected CI|Prepared, not executed|Approved isolated runner, protection policy and exact-source run; no runner registered|
|Operational activation|Prepared, not accepted|Owner storage/access/retention/backup and incident/rollback policy|
|Public package/deployment|Not performed|Separate release authorization after gates; publisher disabled|

The project MIT license does not relicense GPL/native dependencies or Microsoft
binary resources. Possession, a package license field or a hash is not proof of
third-party redistribution rights. Six DLL/LDLL exclusions break legacy loader
controls; raw DLL-to-cache derivation did not reproduce current caches.

No GRUB change, reboot, new host-security mutation, persistent CI credentials,
external specimen upload or service activation is part of this source update.

## Complete per-fixture summary

|Fixture|Family|Outcome|Validation|Accepted|
|---|---|---|---|---|
|case0001|ASPack|extracted|known_answer_verified|yes|
|case0002|Alienyze|partial|partial|no|
|case0003|Amber|timeout|not_checked|no|
|case0004|BeRoEXEPacker|extracted|known_answer_verified|yes|
|case0005|EXpressor|partial|known_answer_verified|no|
|case0006|Enigma Virtual Box|partial|known_answer_verified|no|
|case0007|Eronana Packer|partial|known_answer_verified|no|
|case0008|Exe32pack|partial|known_answer_verified|no|
|case0009|FSG|partial|known_answer_verified|no|
|case0010|JDPack|unsupported|not_checked|no|
|case0011|MEW|extracted|known_answer_verified|yes|
|case0012|MPRESS|extracted|known_answer_verified|yes|
|case0013|Molebox|timeout|not_checked|no|
|case0014|NSPack|extracted|known_answer_verified|yes|
|case0015|Neolite|partial|known_answer_verified|no|
|case0016|PECompact|extracted|known_answer_verified|yes|
|case0017|PEtite|partial|partial|no|
|case0018|Packman|extracted|known_answer_verified|yes|
|case0019|RLPack|unsupported|not_checked|no|
|case0020|TELock|unsupported|not_checked|no|
|case0021|Themida|timeout|not_checked|no|
|case0022|UPX|extracted|known_answer_verified|yes|
|case0023|WinUpack|unsupported|not_checked|no|
|case0024|Yoda-Crypter|unsupported|not_checked|no|
|case0025|Yoda-Protector|unsupported|not_checked|no|
|case0026|ezuri|extracted|known_answer_verified|yes|
|case0027|gzexe|extracted|known_answer_verified|yes|
|case0028|midgetpack|unsupported|not_checked|no|
|case0029|pakkero|partial|partial|no|
|case0030|upx|extracted|known_answer_verified|yes|
|case0031|ward|extracted|known_answer_verified|yes|
|case0032|UPX|extracted|structurally_valid|yes|
|case0033|UPX|extracted|structurally_valid|yes|
|case0034|UPX|extracted|structurally_valid|yes|
|case0035|UPX|extracted|structurally_valid|yes|
|case0036|UPX|extracted|structurally_valid|yes|
|case0037|UPX|extracted|structurally_valid|yes|
|case0038|UPX|extracted|structurally_valid|yes|
|case0039|UPX|extracted|structurally_valid|yes|
|case0040|UPX|extracted_vendor_format|vendor_validated|yes|
|case0041|UPX|extracted_vendor_format|vendor_validated|yes|
|case0042|UPX|extracted|structurally_valid|yes|
|case0043|UPX|extracted|structurally_valid|yes|
|case0044|UPX|extracted|structurally_valid|yes|
|case0045|UPX|extracted|structurally_valid|yes|
|case0046|UPX|extracted_vendor_format|vendor_validated|yes|
|case0047|UPX|extracted|structurally_valid|yes|
|case0048|UPX|extracted|structurally_valid|yes|
|case0049|UPX|extracted|structurally_valid|yes|
|case0050|UPX|extracted|structurally_valid|yes|
|case0051|UPX|extracted|structurally_valid|yes|
|case0052|UPX|extracted|structurally_valid|yes|
|case0053|VMProtect|unsupported|not_checked|no|
|case0054|YZPack|timeout|not_checked|no|

The [JSON matrix](SUPPORTED_MATRIX.json) additionally contains reference gate
booleans, configured decode time and cleanup/reference-visibility facts.
Neither public file includes specimens, recovered binaries or private paths.
