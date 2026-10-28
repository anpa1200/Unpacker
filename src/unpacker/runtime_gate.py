"""Fail closed on a known vulnerable or privileged namespace launcher.

The binary and its installation directory remain operator-controlled trusted
inputs. This version floor is an advisory check, not a hostile-worker audit.
"""
import hashlib,os,re,shutil,stat
from pathlib import Path
from unpacker.process import run_command

MINIMUM_VERSION=(0,12,0)
ADVISORY='https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx'

def require_runtime(selected=None):
    raw=str(selected) if selected is not None else shutil.which('bwrap')
    if not raw:raise ValueError('Patched Bubblewrap >=0.12.0 is required')
    path=Path(raw).resolve(strict=True);mode=path.stat().st_mode
    if not path.is_file() or not os.access(path,os.X_OK) or mode&(stat.S_ISUID|stat.S_ISGID|stat.S_IWOTH):
        raise ValueError('Unprivileged operator-owned Bubblewrap binary required')
    result=run_command([str(path),'--version'],timeout=2,max_output_mb=1)
    text=result['stdout'].strip()
    match=re.fullmatch(r'bubblewrap (\d+)\.(\d+)\.(\d+)',text)
    if result['returncode']!=0 or result['timed_out'] or result.get('output_limit_exceeded') or not match:
        raise ValueError('Cannot verify Bubblewrap version')
    version=tuple(int(v) for v in match.groups())
    if version<MINIMUM_VERSION:
        raise ValueError('Bubblewrap >=0.12.0 required for CVE-2026-87766; installed '+text)
    return {'path':str(path),'version':'.'.join(map(str,version)),
        'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'minimum_version':'0.12.0',
        'advisory':ADVISORY,'security_acceptance':'version floor only; dedicated worker approval still required'}
