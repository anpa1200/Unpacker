"""Bounded tool process supervision. This is not an OS security sandbox."""
from __future__ import annotations
import contextlib, math, os, signal, subprocess, sys, tempfile, threading, time
from pathlib import Path
from unpacker.deadlines import positive_seconds,CLEANUP_GRACE_SECONDS


class ProcessCancelled(KeyboardInterrupt):
    """A default SIGTERM requests owned-job cleanup before exit."""
    def __init__(self,signum):
        self.signum=signum
        super().__init__('Owned command cancelled by signal '+str(signum))


@contextlib.contextmanager
def _sigterm_cancellation():
    # Libraries do not replace an embedding application's custom handler, or
    # change process-global signals from a non-main thread. Nested calls retain
    # the outer handler and still execute each owned-command finally block.
    main=(os.name=='posix' and threading.current_thread() is threading.main_thread())
    previous=signal.getsignal(signal.SIGTERM) if main else None
    installed=main and previous==signal.SIG_DFL
    cancelling=False
    def cancel(signum,frame):
        nonlocal cancelling
        if cancelling:return  # Repeated TERM cannot interrupt bounded cleanup.
        cancelling=True
        raise ProcessCancelled(signum)
    cancel._unpacker_owned_termination=True
    if installed:signal.signal(signal.SIGTERM,cancel)
    try:yield installed or bool(main and getattr(previous,'_unpacker_owned_termination',False))
    finally:
        if installed:signal.signal(signal.SIGTERM,signal.SIG_DFL)


def run_command(command, timeout, max_output_mb=32, cwd=None, input_text=None,
                output_root=None, max_total_output_mb=128, max_output_entries=4096, start_new_session=True, stdout_file=None,env_overrides=None):
    timeout=positive_seconds(timeout)
    if (type(max_output_mb) is not int or not 1<=max_output_mb<=8192 or
        type(max_total_output_mb) is not int or not 1<=max_total_output_mb<=4096 or
        type(max_output_entries) is not int or not 1<=max_output_entries<=100000):
        raise ValueError("Invalid process output budget")
    if env_overrides is None:env_overrides={}
    if not isinstance(env_overrides,dict) or set(env_overrides)-{'XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS'} or any(not isinstance(v,str) or len(v)>4096 or '\x00' in v for v in env_overrides.values()):
        raise ValueError('Invalid supervisor environment overrides')
    with _sigterm_cancellation() as manages_term, tempfile.TemporaryDirectory(prefix="unpacker-process-") as scratch:
        scratch = Path(scratch)
        bootstrap = (
            "import os,resource,sys\n"
            "def cap(kind,value):\n"
            " hard=resource.getrlimit(kind)[1]\n"
            " value=min(value,hard) if hard!=resource.RLIM_INFINITY else value\n"
            " resource.setrlimit(kind,(value,value))\n"
            "cap(resource.RLIMIT_CORE,0)\n"
            "cap(resource.RLIMIT_AS,2147483648)\n"
            f"cap(resource.RLIMIT_FSIZE,{max_output_mb*1024*1024})\n"
            "cap(resource.RLIMIT_NOFILE,128)\n"
            f"cap(resource.RLIMIT_CPU,{max(1,math.ceil(timeout))})\n"
            "os.execv(sys.argv[1],sys.argv[1:])\n"
        )
        with (Path(stdout_file) if stdout_file else scratch/"stdout").open("xb") as stdout, (scratch/"stderr").open("wb") as stderr:
            p=None
            timed_out = False
            output_limit_exceeded = None
            try:
                # Defer TERM across Popen until its owned PID is assigned. The
                # child restores the original mask before exec, so this small
                # critical section never makes the worker immune to TERM.
                mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM}) if manages_term else None
                try:
                    prefix=('import signal\nsignal.pthread_sigmask(signal.SIG_SETMASK,'+repr([int(s) for s in mask])+')\n') if mask is not None else ''
                    cmd = [sys.executable,"-I","-B","-c",prefix+bootstrap,*map(str,command)] if os.name=='posix' else command
                    try:
                        p=subprocess.Popen(cmd,stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                            stdout=stdout,stderr=stderr,cwd=cwd,
                            env={"PATH":os.defpath,"HOME":str(scratch),"LANG":"C.UTF-8",**env_overrides},
                            start_new_session=start_new_session)
                    except OSError as exc:
                        return dict(returncode=-1,timed_out=False,stdout='',stderr=type(exc).__name__)
                finally:
                    if mask is not None:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
                deadline=time.monotonic()+timeout
                from unpacker.budget import check_output_budget
                while True:
                    if output_root is not None:
                        output_limit_exceeded=check_output_budget(output_root,max_total_output_mb*1024*1024,max_output_entries)
                    remaining=deadline-time.monotonic()
                    if output_limit_exceeded or remaining<=0:
                        timed_out=not bool(output_limit_exceeded)
                        try:
                            if os.name == "posix" and start_new_session: os.killpg(p.pid, signal.SIGKILL)
                            else: p.kill()
                        except ProcessLookupError: pass
                        # stdout/stderr are regular files. Reap only in the
                        # bounded finally block; communicate() here could wait
                        # forever after an unsuccessful/slow SIGKILL.
                        break
                    try:
                        p.communicate(input_text.encode() if input_text is not None else None, timeout=min(remaining,.05) if output_root is not None else remaining)
                        if output_root is not None:
                            output_limit_exceeded=check_output_budget(output_root,max_total_output_mb*1024*1024,max_output_entries)
                        break
                    except subprocess.TimeoutExpired:
                        # communicate retains its input buffer across retries.
                        input_text=None
            finally:
                # Cancellation and watchdog errors must not orphan a worker or
                # its descendants. stdout/stderr are regular files, so reaping
                # does not depend on draining a pipe held by a descendant.
                try:
                    if p is not None and os.name == "posix" and start_new_session:
                        os.killpg(p.pid, signal.SIGKILL)
                    elif p is not None and p.poll() is None:
                        p.kill()
                except ProcessLookupError:
                    pass
                try:
                    if p is not None:p.wait(timeout=CLEANUP_GRACE_SECONDS)
                finally:
                    if p is not None and p.stdin is not None and not p.stdin.closed:
                        try: p.stdin.close()
                        except OSError: pass
        def read_log(name):
            with (scratch/name).open("rb") as stream:
                return stream.read(65536).decode("utf-8", "replace")
        return dict(returncode=p.returncode, timed_out=timed_out,
                    output_limit_exceeded=output_limit_exceeded,
                    stdout="" if stdout_file else read_log("stdout"), stderr=read_log("stderr"))
