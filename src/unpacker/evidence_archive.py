"""Validate an untrusted sandbox export before copying regular evidence files."""
import tarfile
from pathlib import Path,PurePosixPath


def unpack_evidence(archive_path,destination,max_bytes,max_entries=4096,max_file_bytes=32*1024*1024):
    try:return _unpack_evidence(archive_path,destination,max_bytes,max_entries,max_file_bytes)
    except tarfile.TarError as exc:raise ValueError('Invalid sandbox evidence archive') from exc


def _unpack_evidence(archive_path,destination,max_bytes,max_entries,max_file_bytes):
    destination=Path(destination).resolve();seen=set();files=set();directories=set();total=0;members=0
    # First pass validates the whole directory before accepting any output bytes.
    with tarfile.open(archive_path,'r:') as archive:
        for member in archive:
            members+=1
            parts=PurePosixPath(member.name).parts
            name=PurePosixPath(member.name).as_posix()
            if (members>max_entries or not parts or len(member.name)>1024 or len(parts)>64 or
                member.name.startswith('/') or '\x00' in member.name or any(p in {'.','..'} for p in member.name.split('/')) or
                name in seen or not (member.isfile() or member.isdir())):
                raise ValueError('Invalid sandbox evidence member')
            seen.add(name)
            if member.isfile():
                # Include each file's minimum filesystem block allocation.
                total+=((member.size+4095)//4096)*4096
                if member.size>max_file_bytes or total>max_bytes:raise ValueError('Sandbox evidence exceeds budget')
            # A previous regular file cannot serve as a parent directory.
            for parent in PurePosixPath(name).parents:
                if str(parent)=='.':continue
                if str(parent) in files:raise ValueError('Evidence file used as a directory')
                directories.add(str(parent))
            if member.isfile():
                if name in directories:raise ValueError('Evidence directory used as a file')
                files.add(name)
            else:directories.add(name)
            # Missing parent headers do not make the directories free:count
            # every distinct filesystem object before accepting any file bytes.
            if len(files)+len(directories)>max_entries:raise ValueError('Sandbox evidence entry budget exceeded')
    with tarfile.open(archive_path,'r:') as archive:
        for member in archive:
            target=destination/member.name
            if member.isdir():target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with archive.extractfile(member) as source,target.open('xb') as output:
                remaining=member.size
                while remaining:
                    block=source.read(min(65536,remaining))
                    if not block:raise ValueError('Truncated evidence file')
                    output.write(block);remaining-=len(block)
            target.chmod(0o600)
    return {'files':len(files),'entries':len(files)+len(directories),'archive_entries':members,'accounted_bytes':total}
