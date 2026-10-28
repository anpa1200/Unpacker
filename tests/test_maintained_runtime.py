"""Known benign CPU/API and rejected-library tests for the reviewed runtime."""
import json,os,shutil,subprocess,sys
from pathlib import Path
import pytest


def run(code):
    env={'PATH':os.defpath,'HOME':'/tmp','LANG':'C.UTF-8','LIBUNICORN_PATH':'/untrusted/ignored'}
    p=subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True,env=env,timeout=8)
    assert p.returncode==0,p.stderr
    return json.loads(p.stdout)


def isolated_bindings(tmp_path,mode):
    import unicorn
    package=Path(unicorn.__file__).resolve().parent
    target=tmp_path/'unicorn';target.mkdir();(target/'lib').mkdir()
    for p in package.glob('*.py'):shutil.copyfile(p,target/p.name)
    core=target/'lib/libunicorn.so';original=package/'lib/libunicorn.so'
    if mode=='tampered':
        shutil.copyfile(original,core)
        with core.open('r+b') as out:
            x=out.read(1);out.seek(0);out.write(bytes([x[0]^1]))
    elif mode=='symlink':core.symlink_to(original)
    elif mode=='growing':shutil.copyfile(original,core)
    return target


def test_reviewed_runtime_imports_without_legacy_packaging_and_executes_benign_code():
    facts=run("""
import sys,ctypes,json,importlib.metadata
class RejectLegacy:
 def find_spec(self,fullname,path=None,target=None):
  if fullname.split('.')[0] in {'distutils','pkg_resources','setuptools'}:raise AssertionError('Legacy packaging import:'+fullname)
sys.meta_path.insert(0,RejectLegacy())
calls=[];load=ctypes.cdll.LoadLibrary
def traced(path):calls.append(path);return load(path)
ctypes.cdll.LoadLibrary=traced
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX
from unipacker.core import Sample,UnpackerEngine
u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(0x1000,0x1000);u.mem_write(0x1000,b'\\xb8\\x2a\\x00\\x00\\x00\\x40\\x90');u.emu_start(0x1000,0x1007,timeout=10000,count=16)
assert u.reg_read(UC_X86_REG_EAX)==43
assert len(calls)==1 and calls[0].startswith('/proc/self/fd/')
assert importlib.metadata.version('unicorn-unipacker')=='1.0.3b7+unpacker.1'
print(json.dumps({'eax':43,'verified_fd_loader':True,'legacy_packaging':False}))
""")
    assert facts=={'eax':43,'verified_fd_loader':True,'legacy_packaging':False}


@pytest.mark.parametrize('mode,reason',[('missing','unavailable'),('tampered','SHA-256 mismatch'),('symlink','unavailable')])
def test_missing_tampered_or_symlink_core_fails_before_dlopen(tmp_path,mode,reason):
    isolated_bindings(tmp_path,mode)
    code="""
import sys,ctypes,json
sys.path.insert(0,ROOT)
def forbidden(path):raise AssertionError('Unverified native library reached dlopen')
ctypes.cdll.LoadLibrary=forbidden
try:import unicorn
except ImportError as e:
 assert REASON in str(e),str(e)
 print(json.dumps({'rejected':True}))
else:raise AssertionError('Unverified core imported')
""".replace('ROOT',repr(str(tmp_path))).replace('REASON',repr(reason))
    assert run(code)=={'rejected':True}


def test_core_verification_reads_are_bounded_even_if_file_grows(tmp_path):
    target=isolated_bindings(tmp_path,'growing');size=(target/'lib/libunicorn.so').stat().st_size
    code="""
import sys,os,ctypes,json
sys.path.insert(0,ROOT);sizes=[]
def growing(fd,n):
 sizes.append(n)
 assert sum(sizes)<=LIMIT+1,'Unbounded integrity read'
 return b'x'*n
os.read=growing
ctypes.cdll.LoadLibrary=lambda path:(_ for _ in ()).throw(AssertionError('Unverified core loaded'))
try:import unicorn
except ImportError as e:
 assert 'changed size' in str(e),str(e)
 assert sum(sizes)==LIMIT+1 and max(sizes)<=65536
 print(json.dumps({'bounded':True}))
else:raise AssertionError('Growing core imported')
""".replace('ROOT',repr(str(tmp_path))).replace('LIMIT',str(size))
    assert run(code)=={'bounded':True}
