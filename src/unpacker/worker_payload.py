"""Fail closed unless the transient controller is inside its expected cgroup."""
import json,re,resource,sys
from pathlib import Path

def inspect_boundary(root=Path('/sys/fs/cgroup'),membership=Path('/proc/self/cgroup')):
    lines=membership.read_text().splitlines()
    if len(lines)!=1 or not lines[0].startswith('0::/'):raise ValueError('Unified cgroup v2 required')
    relative=lines[0][3:]
    if '..' in Path(relative).parts:raise ValueError('Invalid cgroup membership')
    path=root/relative.lstrip('/')
    if not re.fullmatch('unpacker-job-[0-9a-f]{32}\\.service',path.name):raise ValueError('Not an owned transient job')
    values={name:(path/name).read_text().strip() for name in ['memory.max','memory.swap.max','pids.max','cpu.max']}
    if not values['memory.max'].isdigit() or not 0<int(values['memory.max'])<=2147483648:raise ValueError('Memory cap unavailable')
    if values['memory.swap.max']!='0' or not values['pids.max'].isdigit() or not 0<int(values['pids.max'])<=32:raise ValueError('Swap/PID cap unavailable')
    quota,period=values['cpu.max'].split()
    if not quota.isdigit() or not period.isdigit() or not 0<int(quota)<=int(period):raise ValueError('CPU quota unavailable')
    return {'schema':'1','cgroup':str(path),'observed_limits':values,'group_wide':True,'persistent_host_changes':False,
            'rlimit_core':list(resource.getrlimit(resource.RLIMIT_CORE)),'rlimit_nofile':list(resource.getrlimit(resource.RLIMIT_NOFILE))}

def main():
    from unpacker.sandbox_cli import build_parser,main as sandbox_main
    a=build_parser().parse_args()
    try:
        facts=inspect_boundary();a.output_dir.mkdir(parents=True,exist_ok=True)
        with (a.output_dir/('boundary-'+Path(facts['cgroup']).name+'.json')).open('x') as out:json.dump(facts,out,indent=2)
        return sandbox_main()
    except (ValueError,OSError) as exc:
        print('Required job limits were not observed: '+type(exc).__name__,file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
