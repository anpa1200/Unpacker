"""Trusted sandbox controller: export bounded artifacts after analysis terminates."""
import contextlib,sys,tarfile
from pathlib import Path
from unpacker.budget import check_output_budget


def main():
    from unpacker.cli import main as cli
    # Byte stdout is reserved exclusively for the uncompressed evidence archive.
    with contextlib.redirect_stdout(sys.stderr):
        status=cli()
    root=Path('/out')
    # The writable mount is capacity-limited independently of this acceptance gate.
    total=int(sys.argv[sys.argv.index('--max-total-output-mb')+1])*1024*1024
    entries=int(sys.argv[sys.argv.index('--max-output-entries')+1])
    error=check_output_budget(root,total,entries)
    if error:
        print(error,file=sys.stderr);raise SystemExit(2)
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(root.rglob('*')):
            archive.add(path,arcname=str(path.relative_to(root)),recursive=False)
    raise SystemExit(status)
