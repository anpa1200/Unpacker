# Historical non-AI legacy 1.0.0

Runtime, tests, package metadata and original CLI are preserved byte-for-byte
from commit `29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. The preservation branch
changes only GitHub workflow files and adds this note: automatic registry
publication/CI is disabled so creating this GitHub release cannot invoke the
old `release: published` PyPI publisher. No old commit/tag/release is rewritten.

This is a historical prerelease, not new production or security approval.
It has no AI module/entry point, cloud dependency or automatic cloud request.
Use a separate virtual environment from the optional-AI 1.2.0rc13 track.
The newer sandbox, strict acceptance, runtime fixes and AI flags are absent.
Never use this historical snapshot to process hostile files directly on a host.
Project-only artifacts exclude dependencies, Windows resources and specimens.
