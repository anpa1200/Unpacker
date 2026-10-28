# Actual experimental Vagrant/QEMU VM workflow

## Completed proof, 2026-10-27

A genuine QEMU/KVM VM was created through Vagrant 2.4.9 and a task-local
experimental provider. VirtualBox's driver was unavailable; no driver/module
or libvirt service was installed/restarted. Docker was not the VM boundary.

The official Ubuntu Noble image's signed checksum manifest was verified with
the installed cloud-image keyring. Image bytes: 621,284,352; SHA256:

`04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`

The readonly base, private sparse overlay/UEFI variables, task-specific provider
and caches remain local, outside Git. This is not a downloadable production VM.

|Property|Verified configuration|
|---|---|
|Guest|Ubuntu 24.04, kernel 6.8.0-147-generic|
|vCPUs / RAM|2 / 4 GiB; observed MemTotal 4,003,980 KiB|
|Host job|6-GiB memory, swap 0, 64 tasks, one-CPU quota, 180-second runtime|
|Cleanup|Owned transient control group, 5-second stop grace|
|Disk|12-GiB virtual overlay; 8-GiB per-file limit, not aggregate quota|
|Network|No NIC/NAT/bridge; guest saw only `lo`|
|Integration|No shares, clipboard, USB forwarding, VNC or monitor|
|Authentication|No SSH communicator, guest SSH private keys or provider keys|
|Hardening|QEMU seccomp; no host policy/network changes|

First boot produced no acceptance proof. Its console waited on guest
`systemd-networkd-wait-online`; the bounded job ended and was collected. It is
retained as failed evidence. A fresh overlay was edited in an offline libguestfs
appliance to mask only guest wait-online services. No NIC was added. An official
hash-verified public kernel package supplied that appliance's kernel; host
`/boot` permissions and running kernel were unchanged.

The corrected second boot used RC12 core, pefile and pyelftools. The CLI
extracted generated gzip-wrapped, metadata-only ELF data, returning exit 0,
`extracted` and exact original bytes. That fixture had no executable segment
and was never executed. One boot nonce matched. Guest poweroff occurred at
kernel uptime 57.53 seconds; QEMU exited 0, the unit was collected and
`qemu-img check` reported no errors.

It proves one benign static operation, not full runtime, emulation, VM reset,
hostile containment or complete corpus acceptance.

## Existing local inspection commands

Set `UNPACKER_VM_PROOF_WORKSPACE` to the retained task directory containing its
Vagrantfile, adapter, `machine/result.json` and manifest. These commands do not
work from a fresh project checkout alone:

```sh
cd "$UNPACKER_VM_PROOF_WORKSPACE"
VAGRANT_HOME="$PWD/vagrant-home" VAGRANT_CHECKPOINT_DISABLE=1 \
VAGRANT_DEFAULT_PROVIDER=unpacker_qemu vagrant status
```

Last verified state is `poweroff`. The original boot command in that directory
was `vagrant up --provider=unpacker_qemu` with the same environment. The adapter
is deliberately single-use: after a pass it returns the saved result rather
than silently booting again. `halt` targets its exact owned unit. It has no
arbitrary-image/specimen submission interface.

Vagrant copied its publicly shipped insecure test keys into the fresh local
Vagrant home. None was injected into the guest; the task-local copies were
removed. Vagrant may recreate them; never authorize those test keys for a runner.

Local receipts include result, serial console, QEMU/wheel identities, guest-edit
result, host final state and a verified 14-file hash manifest. They contain
private paths and are excluded from public Git; publication-safe facts are here.

## Stopped follow-up, 2026-10-28

A separate prototype was preparing full installed-runtime tests, native benign
CPU checks, guest controls and fresh-overlay reset, using source-only Unipacker
to omit six Windows resources. It was not booted or accepted. Its bundle builder
stopped because the broad executable-file exclusion rejected setuptools'
platform launchers. This is a packaging-policy diagnostic, not evidence of a
malicious dependency. Development was then stopped by the owner. Those unfinished
scripts stay local and are not a supported feature or passed validation result.

## Open gates

The host still reports **Gather Data Sampling: Vulnerable**. No GRUB change or
maintenance reboot occurred. Unknown samples remain blocked. A proposed
separately approved one-time same-kernel `gather_data_sampling=force` boot needs
post-boot mitigation/microcode/AVX verification; this document does not authorize
that reboot or guarantee its result.

Production still needs full guest runtime identity, inner namespace/cgroup
positive/negative controls, aggregate storage limits, cancellation, fresh-overlay
reset, bounded ingress/export, independent validation and the exact 54-case
corpus on the accepted final installed environment. Windows-resource rights,
protected CI and operator acceptance remain separate. No persistent runner,
credentials, exposed endpoint or deployment was created.
