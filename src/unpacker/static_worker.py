"""Process deadlines for owned static detection and artifact parsing.

This is a resource boundary, not an OS security sandbox. Callers supplying parsed
objects use the explicitly low-level in-process detector path.
"""
import contextlib,dataclasses,json,sys
from pathlib import Path
from unpacker.process import run_command


def invoke(payload, timeout):
    package_root=str(Path(__file__).resolve().parents[1])
    code='import sys;sys.path.insert(0,'+repr(package_root)+');from unpacker.static_worker import main;main()'
    result=run_command([sys.executable,'-I','-B','-c',code],timeout=timeout,max_output_mb=1,input_text=json.dumps(payload))
    if result['timed_out']:return None,'Static analysis hard deadline exceeded'
    if result['returncode']!=0:return None,'Static analysis worker failed'
    try:return json.loads(result['stdout']),None
    except (TypeError,ValueError):return None,'Invalid static analysis result'


def main():
    payload=json.loads(sys.stdin.read(65537))
    with contextlib.redirect_stdout(sys.stderr):
        if payload['operation']=='detect':
            from unpacker.detector.pipeline import DetectorPipeline
            pipeline=DetectorPipeline(**payload['settings'])
            result=dataclasses.asdict(pipeline._detect_in_process(Path(payload['sample'])))
        elif payload['operation']=='validate':
            from unpacker.validation import _validate_artifact_in_process
            from unpacker.types import UnpackOptions
            settings=payload['settings'];settings['output_dir']=Path(settings['output_dir'])
            result=_validate_artifact_in_process(Path(payload['sample']),Path(payload['path']),UnpackOptions(**settings),payload['kind'])
        else:raise ValueError('Unknown static operation')
    print(json.dumps(result))
