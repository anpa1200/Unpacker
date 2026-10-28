"""Linux namespace-isolated entry point; fails closed when isolation is unavailable."""
import argparse,json,shutil,site,sys,tempfile,time
from pathlib import Path
from unpacker.types import DEFAULT_DECODE_TIMEOUT_SECONDS
from unpacker.deadlines import DeadlinePlan
from unpacker.process import run_command,ProcessCancelled
from unpacker.validation import sha256


def _base_site_mounts(prefix):
    """Mask existing base-package directories at every visible projection.

    Debian's dist-packages layout differs from Conda/upstream site-packages.
    An absent target needs no mask and cannot be created below a readonly bind.
    """
    paths=set()
    for value in site.getsitepackages(prefixes=[str(prefix)]):
        host=Path(value)
        if not host.is_dir():continue
        if host.is_relative_to(prefix/'lib'):
            paths.add(str(Path('/runtime/lib')/host.relative_to(prefix/'lib')))
        if any(host.is_relative_to(root) for root in [Path('/usr'),Path('/lib'),Path('/lib64')]):
            paths.add(str(host))
    return sorted(paths)


def build_command(sample,output,arguments,reference=None,rootfs=None,max_total_output_mb=128,*,payload_code=None,payload_arguments=None,validation_source=None,bubblewrap=None):
    tool=str(bubblewrap) if bubblewrap is not None else shutil.which('bwrap')
    if tool is None or sys.platform!='linux':raise ValueError('Linux Bubblewrap isolation is required')
    # A venv contains site-packages, not a full standard library. /app below
    # supplies the installed package/dependencies; the base Python supplies the
    # standard library and native runtime. This also works outside a venv.
    prefix=Path(sys.base_prefix)
    command=[tool,'--unshare-all','--unshare-user','--disable-userns','--die-with-parent','--new-session','--cap-drop','ALL',
        '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind-try','/lib64','/lib64',
        '--dir','/runtime/bin','--ro-bind',sys.executable,'/runtime/bin/python3',
        '--ro-bind',str(prefix/'lib'),'/runtime/lib',
        '--ro-bind',str(Path(__file__).resolve().parent.parent),'/app',
        '--ro-bind',str(sample.resolve()),'/input.bin','--size',str(max_total_output_mb*1024*1024),'--tmpfs','/out',
        '--proc','/proc','--dev','/dev','--size','67108864','--tmpfs','/tmp',
        '--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/tmp','--setenv','LANG','C.UTF-8','--chdir','/out']
    # The selected /app dependencies are explicit; base .pth/global package
    # directories must remain empty RO,including distro-specific layouts.
    for target in _base_site_mounts(prefix):
        command+=['--tmpfs',target,'--remount-ro',target]
    if Path('/etc/alternatives/upx').exists():
        command+=['--dir','/etc/alternatives','--symlink',str(Path('/etc/alternatives/upx').resolve()),'/etc/alternatives/upx']
    if reference:
        command+=['--ro-bind',str(reference.resolve()),'/reference.bin']
        arguments+=['--reference','/reference.bin']
    if rootfs:
        command+=['--ro-bind',str(rootfs.resolve()),'/rootfs']
        arguments+=['--rootfs','/rootfs']
    if validation_source is not None:
        if payload_code is None:raise ValueError('Validation source requires trusted validator payload')
        command+=['--ro-bind',str(validation_source.resolve()),'/source.bin']
    code="import sys;sys.path.insert(0,'/app');from unpacker.sandbox_payload import main;main()"
    if payload_code is not None:
        return command+['/runtime/bin/python3','-I','-B','-c',payload_code,*(payload_arguments or [])]
    return command+['/runtime/bin/python3','-I','-B','-c',code,'/input.bin','-o','/out/artifacts','--json','--report-file','/out/report.json',*arguments]


def build_parser():
    p=argparse.ArgumentParser(description='Run Unpacker in a networkless Linux namespace sandbox')
    from unpacker import __version__
    p.add_argument("--version", action="version", version="unpacker-sandbox "+__version__)
    p.add_argument('sample',type=Path)
    p.add_argument('-o','--output-dir',type=Path,default=Path('unpacked'))
    p.add_argument('--timeout',type=float,default=DEFAULT_DECODE_TIMEOUT_SECONDS,help="Per-backend decode deadline in seconds (default: 60)")
    p.add_argument('--total-timeout',type=float,default=300)
    p.add_argument('--max-layers',type=int,default=5)
    p.add_argument('--max-total-output-mb',type=int,default=128)
    p.add_argument('--max-output-entries',type=int,default=4096)
    p.add_argument('--allow-emulation',action='store_true')
    p.add_argument('--guest-yesno-answer',choices=('yes','no'),default='no')
    p.add_argument('--guest-module-profile',choices=('named-exports','core-strict'),default='named-exports')
    p.add_argument('--packer')
    p.add_argument('--reference',type=Path)
    p.add_argument('--rootfs',type=Path)
    p.add_argument('--bubblewrap',type=Path,help='Operator-installed unprivileged Bubblewrap >=0.12.0; no unsafe fallback')
    p.add_argument('--require-accepted',action='store_true',help='Exit zero only for independently accepted reconstruction, not completion/no-packing/unverified outcomes')
    return p


def main():
    p=build_parser()
    a=p.parse_args()
    try:
        deadlines=DeadlinePlan(a.timeout,a.total_timeout)
        controller_deadline=time.monotonic()+deadlines.job_seconds
        if not 1<=a.max_total_output_mb<=4096 or not 1<=a.max_output_entries<=100000 or not 1<=a.max_layers<=32:raise ValueError('Invalid output/layer budget')
        from unpacker.runtime_gate import require_runtime
        runtime=require_runtime(a.bubblewrap)
        if not a.sample.is_file() or a.sample.stat().st_size>32*1024*1024:raise ValueError('Invalid input')
        a.output_dir.mkdir(parents=True,exist_ok=True)
        output=Path(tempfile.mkdtemp(prefix='run-',dir=a.output_dir)).resolve()
        args=['--timeout',str(a.timeout),'--total-timeout',str(a.total_timeout),'--max-layers',str(a.max_layers),'--max-total-output-mb',str(a.max_total_output_mb),'--max-output-entries',str(a.max_output_entries)]
        args+=['--guest-yesno-answer',a.guest_yesno_answer]
        args+=['--guest-module-profile',a.guest_module_profile]
        if a.allow_emulation:args+=['--allow-emulation']
        if a.packer:args+=['--packer',a.packer]
        from unpacker.evidence_archive import unpack_evidence
        from unpacker.report_integrity import snapshot_input,load_report,check_report,verify_artifacts,accepted_recovery,COMPLETION_STATUSES
        with tempfile.TemporaryDirectory(prefix='unpacker-job-') as scratch:
            scratch=Path(scratch)
            sample=scratch/'input.bin';input_digest=snapshot_input(a.sample,sample)
            reference=None;reference_digest=None
            if a.reference:
                reference=scratch/'reference.bin';reference_digest=snapshot_input(a.reference,reference)
            # The unknown-input worker never sees the reference. Only the later,
            # separately jailed pure-data validator receives that read-only file.
            command=build_command(sample,output,args,None,a.rootfs,a.max_total_output_mb,bubblewrap=runtime['path'])
            (output/'invocation.json').write_text(json.dumps({'input_sha256':input_digest,'original_input':str(a.sample.absolute()),'input_snapshot':True,'namespace_runtime':runtime,'reference_sha256':reference_digest,'reference_visible_to_analysis_worker':False,'command':command,'deadlines':deadlines.facts()},indent=2))
            archive=Path(scratch)/'evidence.tar'
            # USTAR overhead is bounded by the validated entry-count ceiling.
            spool_mb=a.max_total_output_mb+(a.max_output_entries*1024+65535)//1048576+2
            result=run_command(command,timeout=deadlines.sandbox_seconds,max_output_mb=spool_mb,stdout_file=archive)
            if archive.exists() and archive.stat().st_size:
                try: result['evidence_export']=unpack_evidence(archive,output,a.max_total_output_mb*1024*1024,a.max_output_entries)
                except (ValueError,OSError) as exc:
                    result['export_error']=type(exc).__name__
            else:result['export_error']='Missing evidence archive'
            if not result.get('export_error') and not (output/'report.json').is_file():
                result['export_error']='Missing analysis report'
            if not result.get('export_error'):
                try:
                    report=load_report(output/'report.json')
                    artifacts=check_report(report,output,input_digest,a.max_layers)
                    receipt=verify_artifacts(report,artifacts,sample,reference,output,controller_deadline,bubblewrap=runtime['path'])
                    (output/'report.json').replace(output/'worker-report.json')
                    (output/'report.json').write_text(json.dumps(report,indent=2))
                    (output/'integrity.json').write_text(json.dumps(receipt,indent=2))
                    result['report_integrity']='verified';result['accepted_recovery']=accepted_recovery(report)
                    result['completion_status']=report['status']
                except (ValueError,OSError,TypeError,KeyError) as exc:
                    result['export_error']='Invalid report/artifact integrity: '+type(exc).__name__
            result['sandbox_path_mapping']={'/out':str(output)}
        (output/'process.json').write_text(json.dumps(result,indent=2))
        print(f'Proof directory: {output}')
        # Raw specimen/worker logs stay in bounded JSON evidence, not the
        # terminal: control sequences and pre-validation claims are untrusted.
        print('Outcome: '+str(result.get('completion_status','unavailable'))+'; accepted_recovery='+str(result.get('accepted_recovery',False)))
        if result['timed_out'] or result.get('output_limit_exceeded') or result.get('export_error'):return 1
        # A setup failure is never retried outside isolation.
        if a.require_accepted and not result.get('accepted_recovery'):return 1
        return 0 if result['returncode']==0 and result.get('completion_status') in COMPLETION_STATUSES else 1
    except ProcessCancelled as exc:
        if 'output' in locals():
            (output/'cancellation.json').write_text(json.dumps({'status':'cancelled','signal':exc.signum,'exit_code':128+exc.signum}))
        print('Sandbox job cancelled by signal '+str(exc.signum),file=sys.stderr)
        return 128+exc.signum
    except (ValueError,OSError) as exc:
        print(f'Isolation/input error: {type(exc).__name__}: {exc}',file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
