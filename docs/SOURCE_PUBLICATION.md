# Source-publication scope — 2026-10-28

The owner stopped development and requested documentation, commit and push.
This change preserves the latest verified RC12 application implementation and
tests, replacing the earlier RC4 source state while retaining original local
working files and frozen evidence outside Git. It adds current usage,
architecture, results, VM, issue and operations documentation.

Application/runtime Python files are byte-compared against frozen RC12.
Documentation/metadata/workflow corrections one private-path test literal and test-only EOF whitespace
are publication changes. No fresh package was built and no full suite or corpus
was rerun after those changes. Historical package test receipts must not be
misrepresented as a new Git-commit-wide CI result.

Included: project Python source, benign synthetic test definitions, configuration,
exact requirement/provenance declarations, manual CI proposals and technical
public documentation. The public 54-fixture summary omits input/reference hashes,
private paths/identifiers, raw logs and recovered artifacts.

Excluded and preserved locally: provider/sudo credentials and environment files;
private machine receipts/configuration; licensed or unresolved Windows DLL/LDLL
resources; corpus specimens/recovered executables; native wheels/binaries/source-
offer archives; VM base images/disks/ISOs, caches and virtual environments; and
unfinished full-runtime/reset prototype scripts. Those scripts never produced an
accepted bundle or VM run and are not promoted into supported capabilities.
No unrelated project or existing container is changed.

The checked-in publisher is disabled; tests are manual and require an accepted
private isolated runner. This push creates no release tag, PyPI publication,
runner credential, security-policy mutation, reboot or deployment. Current
production gates, including GDS and resource rights, remain explicit.
