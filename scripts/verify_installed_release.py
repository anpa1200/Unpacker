"""Verify an installed wheel outside the checkout with benign fixtures only.

Run with the environment's Python -I -B. Never installs dependencies, reads
credentials, calls an LLM or executes an input program.
"""
import argparse
import gzip
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
import zipfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--minimum-tests',type=int,default=939)
    parser.add_argument('--sandbox',action='store_true')
    parser.add_argument('--production-worker',action='store_true',help='Require the cgroup-supervised worker for benign sandbox checks')
    parser.add_argument('--bubblewrap',type=Path)
    args=parser.parse_args()
    if args.production_worker and not args.sandbox:parser.error("--production-worker requires --sandbox")
    runtime_args=["--bubblewrap",args.bubblewrap.resolve()] if args.bubblewrap else []
    boundary_module="unpacker.worker_cli" if args.production_worker else "unpacker.sandbox_cli"
    source=args.source_root.resolve();out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    import unpacker
    package=Path(unpacker.__file__).resolve().parent
    if source==package or source in package.parents:
        raise ValueError('Checkout import cannot validate an installed release')
    version=importlib.metadata.version('1200km-unpacker')
    if unpacker.__version__!=version:raise ValueError('Distribution version mismatch')
    with zipfile.ZipFile(args.wheel) as archive:
        expected={name:hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()
                  if name.startswith('unpacker/') and name.endswith('.py')}
    actual={str(p.relative_to(package.parent)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in package.rglob('*.py')}
    if not expected or actual!=expected:raise ValueError('Installed files differ from wheel')
    checkout={'unpacker/'+str(p.relative_to(source/'src/unpacker')):hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (source/'src/unpacker').rglob('*.py')}
    if checkout!=expected:raise ValueError('Wheel differs from selected source snapshot')
    suite=out/'suite';suite.mkdir()
    shutil.copytree(source/'tests',suite/'tests',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(source/'scripts',suite/'scripts',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(source/'config',suite/'config')
    (suite/'pytest.ini').write_text('[pytest]\ntestpaths = tests\n')
    (suite/'conftest.py').write_text('import pathlib,json,unpacker\n'
        'def pytest_sessionstart(session):\n    p=pathlib.Path(unpacker.__file__).resolve()\n'
        f'    assert p.parent==pathlib.Path({str(package)!r})\n'
        f'    pathlib.Path({str(out/"pytest-import-origin.json")!r}).write_text(json.dumps({{"package_origin":str(p)}}))\n')
    env={'PATH':os.defpath,'HOME':str(out),'LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
         'PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1','PIP_NO_INDEX':'1'}
    checks=[]
    def run(label,arguments,timeout=30,expected_exit=0):
        result=subprocess.run([str(x) for x in arguments],cwd=suite,env=env,
                              text=True,capture_output=True,timeout=timeout)
        checks.append({'name':label,'returncode':result.returncode})
        (out/(label+'.stdout.txt')).write_text(result.stdout)
        (out/(label+'.stderr.txt')).write_text(result.stderr)
        if result.returncode!=expected_exit:raise ValueError('Check failed: '+label)
        return result
    record={'package_origin':str(package),'version':version,'wheel_sha256':hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
            'source_hashes':expected,'checks':checks,'sandbox_requested':args.sandbox,'production_worker_requested':args.production_worker,'status':'started'}
    try:
        junit=out/'installed-tests.xml'
        run('installed-tests',[sys.executable,'-I','-B','-m','pytest','-c',suite/'pytest.ini',
            '-p','no:cacheprovider','--junitxml='+str(junit),'-q',suite/'tests'],timeout=180)
        gate=runpy.run_path(str(source/'scripts/check_release_tests.py'))['check']
        record['tests']=gate(junit,args.minimum_tests)
        for module in ('unpacker.cli','unpacker.sandbox_cli','unpacker.ai.cli','unpacker.worker_cli'):
            name=module.replace('.','-')
            run(name+'-help',[sys.executable,'-I','-B','-m',module,'--help'])
            result=run(name+'-version',[sys.executable,'-I','-B','-m',module,'--version'])
            if version not in result.stdout:raise ValueError('CLI version mismatch')
        # ELF metadata plus one read-only segment; no entry point or instructions.
        elf=b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0,64,0,0,64,56,1,64,0,0)
        elf+=struct.pack('<IIQQQQQQ',1,4,0,0x400000,0x400000,120,120,4096)
        original=out/'benign-original.bin';original.write_bytes(elf)
        wrapper=out/'benign-wrapper.bin';wrapper.write_bytes(b'#!/bin/sh\n# tail gzip fixture, never executed\n'+gzip.compress(elf,mtime=0))
        direct=out/'direct';direct.mkdir()
        run('benign-static-extraction',[sys.executable,'-I','-B','-m','unpacker.cli',wrapper,
            '-o',direct,'--packer','gzexe','--reference',original,'--json','--report-file',direct/'report.json',
            '--timeout','60','--total-timeout','75','--max-total-output-mb','32'])
        report=json.loads((direct/'report.json').read_text())
        if report['status']!='extracted':raise ValueError('Benign extraction not accepted')
        if report['layers'][0]['unpack_result']['validation_status']!='known_answer_verified':
            raise ValueError('Reference comparison not exercised')
        if Path(report['final_path']).read_bytes()!=elf:raise ValueError('Extracted bytes differ')
        preview=run('offline-ai-preview',[sys.executable,'-I','-B','-m','unpacker.ai.cli',
            direct/'report.json','--from-report','--preview','--env-file',out/'absent.env'])
        if json.loads(preview.stdout)['schema_version']!='2':raise ValueError('Offline preview failed')
        invalid=out/'invalid.bin';invalid.write_bytes(b'MZ'+bytes(64))
        run('malformed-input-fails',[sys.executable,'-I','-B','-m','unpacker.cli',invalid,
            '-o',out/'invalid-output','--json'],expected_exit=1)
        if args.sandbox:
            isolated=out/'sandbox';isolated.mkdir()
            run('real-sandbox-benign-extraction',[sys.executable,'-I','-B','-m',boundary_module,
                wrapper,'-o',isolated,'--packer','gzexe','--reference',original,'--timeout','60',
                '--total-timeout','90','--max-total-output-mb','32',*runtime_args],timeout=135)
            reports=list(isolated.glob('run-*/report.json'))
            if len(reports)!=1 or json.loads(reports[0].read_text())['status']!='extracted':
                raise ValueError('Sandbox did not export verified benign extraction')
        if args.sandbox:
            extended=out/'sandbox-180';extended.mkdir()
            run('real-sandbox-extended-profile',[sys.executable,'-I','-B','-m',boundary_module,
                wrapper,'-o',extended,'--packer','gzexe','--reference',original,'--timeout','180',
                '--total-timeout','210','--max-total-output-mb','32',*runtime_args],timeout=255)
            reports=list(extended.glob('run-*/report.json'))
            if len(reports)!=1 or json.loads(reports[0].read_text())['status']!='extracted':
                raise ValueError('Extended-profile benign sandbox failed')
            invocation=json.loads((reports[0].parent/'invocation.json').read_text())
            if invocation['deadlines']['sandbox_watchdog_seconds']!=215:
                raise ValueError('Extended-profile watchdog mismatch')
        if args.production_worker:
            for folder in (out/'sandbox',out/'sandbox-180'):
                jobs=list(folder.glob('unpacker-job-*.json'))
                if len(jobs)!=1 or json.loads(jobs[0].read_text()).get('collected') is not True:
                    raise ValueError('Production worker did not prove cgroup cleanup')
                integrity=list(folder.glob('run-*/integrity.json'))
                if len(integrity)!=1 or json.loads(integrity[0].read_text()).get('accepted_recovery') is not True:
                    raise ValueError('Production worker independent acceptance missing')
        record['status']='passed'
    finally:
        (out/'verification.json').write_text(json.dumps(record,indent=2))
    print(json.dumps({k:v for k,v in record.items() if k!='source_hashes'},indent=2))


if __name__=='__main__':main()
