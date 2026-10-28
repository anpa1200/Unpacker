"""Transient user cgroup + networkless namespace launcher; no weaker fallback."""
import json,os,re,shutil,signal,sys,uuid
from pathlib import Path
from unpacker.process import run_command,ProcessCancelled,_sigterm_cancellation
from unpacker.sandbox_cli import build_parser
from unpacker.deadlines import DeadlinePlan

def build_job(arguments,unit,memory_mb=2048,tasks=32):
    arguments=list(arguments)
    if '--require-accepted' not in arguments:arguments.append('--require-accepted')
    if sys.platform!='linux' or not shutil.which('systemd-run') or not shutil.which('systemctl'):raise ValueError('Linux user service manager required')
    if type(memory_mb) is not int or not 64<=memory_mb<=2048 or type(tasks) is not int or not 8<=tasks<=32:raise ValueError('Invalid job resource limits')
    if not re.fullmatch('unpacker-job-[0-9a-f]{32}',unit):raise ValueError('Invalid owned unit identity')
    parser=build_parser();a=parser.parse_args(arguments);deadlines=DeadlinePlan(a.timeout,a.total_timeout)
    if not 1<=a.max_total_output_mb<=4096 or not 1<=a.max_output_entries<=100000:raise ValueError('Invalid job output limits')
    runtime=deadlines.job_seconds+20
    spool_mb=a.max_total_output_mb+(a.max_output_entries*1024+65535)//1048576+2
    properties={'MemoryMax':memory_mb*1024*1024,'MemorySwapMax':0,'TasksMax':tasks,'CPUQuota':'100%',
        'RuntimeMaxSec':runtime,'KillMode':'control-group','TimeoutStopSec':5,'SendSIGKILL':'yes',
        'LimitCORE':0,'LimitNOFILE':128,'LimitFSIZE':spool_mb*1024*1024}
    command=[shutil.which('systemd-run'),'--user','--quiet','--wait','--pipe','--collect','--unit='+unit]
    command+=['--property='+k+'='+str(v) for k,v in properties.items()]
    # Neither manager credentials nor caller environment enter the controller.
    command+=['/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME=/tmp','LANG=C.UTF-8',sys.executable,'-I','-B','-m','unpacker.worker_payload',*arguments]
    return command,properties,runtime+10

def main():
    arguments=sys.argv[1:]
    if arguments==['--version']:
        from unpacker import __version__
        print('unpacker-worker '+__version__);return 0
    if arguments in [['--help'],['-h']]:
        p=build_parser();p.description=__doc__;p.print_help();return 0
    parser=build_parser();a=parser.parse_args(arguments)
    unit='unpacker-job-'+uuid.uuid4().hex
    env={'XDG_RUNTIME_DIR':'/run/user/'+str(os.getuid()),'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/'+str(os.getuid())+'/bus'}
    record={'unit':unit,'transient_only':True,'persistent_host_changes':False,'status':'starting'}
    try:
        command,properties,timeout=build_job(arguments,unit)
        systemctl=shutil.which('systemctl')
        record['properties']=properties
        a.output_dir.mkdir(parents=True,exist_ok=True)
        status=1
        with _sigterm_cancellation():
            try:
                result=run_command(command,timeout=timeout,max_output_mb=2,env_overrides=env)
                record['controller']=result
                if result['stdout']:print(result['stdout'],end='')
                if result['stderr']:print(result['stderr'],file=sys.stderr,end='')
                status=0 if result['returncode']==0 and not result['timed_out'] else 1
                record['status']='completed' if status==0 else 'unsuccessful'
            except ProcessCancelled as exc:
                status=128+exc.signum;record.update(status='cancelled',signal=exc.signum)
            except KeyboardInterrupt:
                status=130;record.update(status='cancelled',signal=signal.SIGINT)
            finally:
                # Stop the exact owned cgroup even if descendants called setsid.
                # An absent/auto-collected unit is normal; never target another.
                previous={sig:signal.signal(sig,signal.SIG_IGN) for sig in [signal.SIGTERM,signal.SIGINT]}
                try:
                    cleanup=run_command([systemctl,'--user','stop',unit+'.service'],timeout=8,max_output_mb=1,env_overrides=env)
                    record['cleanup']=cleanup
                    probe=run_command([systemctl,'--user','show',unit+'.service','--property=LoadState'],timeout=3,max_output_mb=1,env_overrides=env)
                    record['collected']=probe['stdout'].strip()=='LoadState=not-found'
                    if not record['collected']:status=1;record['status']='cleanup_failed'
                finally:
                    for sig,handler in previous.items():signal.signal(sig,handler)
        record['exit_code']=status
        with (a.output_dir/(unit+'.json')).open('x') as out:json.dump(record,out,indent=2)
        return status
    except (ValueError,OSError) as exc:
        print('Required job boundary unavailable: '+type(exc).__name__,file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
