# Security policy

## Supported scope

`main` currently preserves research candidate 1.2.0rc12. Maintenance of source
is not approval for production hostile-file handling. No universal unpacking,
malware safety or exploit-free sandbox guarantee is provided. Package versions,
native dependencies and worker environments require separate acceptance.
See [current gates](docs/CURRENT_STATUS.md) and [trust boundaries](docs/ARCHITECTURE.md).

## Reporting

Report vulnerabilities privately to `1200km@gmail.com`; do not post a public
issue containing exploit details, private specimens, provider keys or case data.
Default coordinated disclosure window: 90 days. This is not a response-time SLA.

## Handling inputs and dependencies

Use an approved disposable boundary; never execute a specimen or recovered
artifact on an everyday host. Do not weaken namespace/network/capability limits
because a sample fails. Stop submissions after suspected containment/integrity
failure, preserve evidence and reimage the worker. Private provider disclosure
requires applicable authorization even for structural metadata.

A dependency/license inventory, hash or zero-finding registry scan does not
establish rights, behavioral correctness or comprehensive native/OS security.
No unlicensed Windows resource, credential, specimen or VM disk belongs in Git.
