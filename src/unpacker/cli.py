"""CLI with explicit outcomes, JSON reports and opt-in emulation."""
import argparse,dataclasses,json,sys
from pathlib import Path
from unpacker.types import DEFAULT_DECODE_TIMEOUT_SECONDS
from unpacker.orchestrator import run
from unpacker.process import ProcessCancelled


def build_parser():
    p=argparse.ArgumentParser(description="Bounded packed-file extraction and evidence reporting")
    from unpacker import __version__
    p.add_argument("--version", action="version", version="unpacker "+__version__)
    p.add_argument("sample",type=Path)
    p.add_argument("-o","--output-dir",type=Path,default=Path("unpacked"))
    p.add_argument("--max-layers",type=int,default=5)
    p.add_argument("--confidence",type=float,default=.5)
    p.add_argument("--timeout",type=float,default=DEFAULT_DECODE_TIMEOUT_SECONDS,help="Per-backend decode deadline in seconds (default: 60)")
    p.add_argument("--total-timeout",type=float,default=300)
    p.add_argument("--max-output-mb",type=int,default=32)
    p.add_argument("--max-total-output-mb",type=int,default=128)
    p.add_argument("--max-output-entries",type=int,default=4096)
    p.add_argument("--allow-emulation",action="store_true",help="Explicitly permit emulation; run inside an OS sandbox or VM")
    p.add_argument("--guest-yesno-answer",choices=("yes","no"),default="no",help="Explicit guest MessageBox YES/NO response; recorded, default no")
    p.add_argument('--guest-module-profile',choices=('named-exports','core-strict'),default='named-exports',help='Resident named-API export views or only the three supplied core DLL images')
    p.add_argument("--packer",help="Analyst-selected backend hint; recorded separately from detection")
    p.add_argument("--reference",type=Path,help="Optional known original for code/import/entry comparison")
    p.add_argument("--json",action="store_true",help="Machine-readable report")
    p.add_argument("--rootfs",type=Path,help="Explicit Windows rootfs for optional Qiling")
    p.add_argument("--report-file",type=Path,help="Write full JSON evidence to a new file")
    p.add_argument("--config",type=Path,help="Explicit bounded YAML configuration; CLI overrides it")
    p.add_argument('--require-accepted',action='store_true',help='Exit zero only for accepted reconstruction; completion alone does not satisfy this mode')
    return p


def main():
    p=build_parser()
    args=p.parse_args()
    try:
        config={}
        if args.config:
            from unpacker.configuration import load_config
            config=load_config(args.config)
        mapping={'max_layers':('--max-layers',args.max_layers),'confidence_threshold':('--confidence',args.confidence),
                 'timeout_seconds':('--timeout',args.timeout),'total_timeout_seconds':('--total-timeout',args.total_timeout),
                 'max_total_output_size_mb':('--max-total-output-mb',args.max_total_output_mb),
                 'max_output_entries':('--max-output-entries',args.max_output_entries),
                 'max_output_size_mb':('--max-output-mb',args.max_output_mb),'allow_emulation':('--allow-emulation',args.allow_emulation)}
        effective={key:(value if any(a==flag or a.startswith(flag+'=') for a in sys.argv[1:]) else config.get(key,value)) for key,(flag,value) in mapping.items()}
        report=run(args.sample,args.output_dir,**effective,packer_id=args.packer,reference=args.reference,rootfs=args.rootfs,guest_yesno_answer=args.guest_yesno_answer,guest_module_profile=args.guest_module_profile)
        serialized=json.dumps(dataclasses.asdict(report),default=lambda o:str(o) if isinstance(o,Path) else None,indent=2)
        if args.report_file:
            with args.report_file.open('x') as f:f.write(serialized)
        if args.json:
            print(serialized)
        else:
            print(f"Outcome: {report.status}; stop: {report.stop_reason}")
            for i,layer in enumerate(report.layers,1):
                print(f"Layer {i}: {layer.packer_id} -> {layer.unpack_result.status}; validation={layer.unpack_result.validation_status}")
            if report.final_path:print(f"Artifact: {report.final_path}")
            if report.error:print(f"Error: {report.error}",file=sys.stderr)
        from unpacker.report_integrity import accepted_recovery,COMPLETION_STATUSES
        if args.require_accepted and not accepted_recovery(json.loads(serialized)):return 1
        return 0 if report.status in COMPLETION_STATUSES else 1
    except ProcessCancelled as exc:
        print('Analysis cancelled by signal '+str(exc.signum),file=sys.stderr)
        return 128+exc.signum
    except (OSError,ValueError) as exc:
        print(f"Input/configuration error: {type(exc).__name__}",file=sys.stderr)
        return 2


if __name__=="__main__":raise SystemExit(main())
