"""Controller-owned provenance and independent, isolated artifact validation."""
import hashlib,json,math,os,re,stat,sys,time
from pathlib import Path,PurePosixPath

COMPLETION_STATUSES={'extracted','extracted_vendor_format','extracted_unverified','extracted_with_residual_evidence','no_packing_evidence'}
TERMINAL_STATUSES=COMPLETION_STATUSES|{'partial','failed','unsupported','timeout','input_error','parse_error','unsupported_format','inconclusive','backend_error','dependency_error','resource_limit','cancelled'}
QUALITY={'known_answer_verified','structurally_valid','vendor_validated'}

def snapshot_input(source,destination,max_bytes=32*1024*1024):
    """Open once, reject links/special files, cap and hash the exact mounted copy."""
    source,destination=Path(source),Path(destination)
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>max_bytes:raise ValueError('Invalid input snapshot')
        digest=hashlib.sha256();count=0
        with os.fdopen(fd,'rb',closefd=False) as inp,destination.open('xb') as out:
            destination.chmod(0o600)
            while True:
                data=inp.read(65536)
                if not data:break
                count+=len(data)
                if count>max_bytes:raise ValueError('Input grew beyond budget')
                digest.update(data);out.write(data)
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
            raise ValueError('Input changed during snapshot')
        return digest.hexdigest()
    finally:os.close(fd)

def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON key')
        result[key]=value
    return result

def _invalid_constant(value):raise ValueError('Nonfinite JSON value')

def _finite_float(value):
    number=float(value)
    if not math.isfinite(number):raise ValueError('Nonfinite JSON number')
    return number

def _load_json(raw):
    """One finite, unambiguous contract for producer and validator evidence."""
    try:value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=_invalid_constant,parse_float=_finite_float)
    except (RecursionError,UnicodeError) as exc:raise ValueError('Invalid evidence JSON') from exc
    # Iterators keep memory proportional to depth rather than array width.
    stack=[(iter((value,)),0)]
    while stack:
        values,depth=stack[-1]
        try:child=next(values)
        except StopIteration:stack.pop();continue
        if isinstance(child,(dict,list)):
            if depth>=64:raise ValueError('Evidence JSON nesting limit exceeded')
            stack.append((iter(child.values() if isinstance(child,dict) else child),depth+1))
    return value

def load_report(path,max_bytes=4*1024*1024):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=max_bytes:raise ValueError('Invalid report size/type')
    return _load_json(p.read_bytes())

def artifact_path(value,output):
    if not isinstance(value,str) or '\\' in value or '\x00' in value:raise ValueError('Invalid artifact path')
    parts=PurePosixPath(value).parts
    if parts[:3]!=('/','out','artifacts') or len(parts)<4 or any(p in {'.','..',''} for p in value.split('/')[1:]):raise ValueError('Artifact outside export')
    p=Path(output).joinpath(*parts[2:])
    for parent in [p,*p.parents]:
        if parent==Path(output).parent:break
        if parent.is_symlink():raise ValueError('Artifact symlink')
    if not p.is_file() or not p.resolve().is_relative_to(Path(output).resolve()/'artifacts'):raise ValueError('Missing owned artifact')
    return p

def _sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as inp:
        for block in iter(lambda:inp.read(65536),b''):digest.update(block)
    return digest.hexdigest()

def check_report(report,output,input_sha,max_layers=32,max_artifact_bytes=32*1024*1024):
    if not isinstance(report,dict) or report.get('sample_path')!='/input.bin' or report.get('status') not in TERMINAL_STATUSES:raise ValueError('Invalid report envelope')
    layers=report.get('layers')
    if not isinstance(layers,list) or len(layers)>max_layers:raise ValueError('Invalid layer list')
    previous=input_sha;artifacts=[]
    for layer in layers:
        if not isinstance(layer,dict) or layer.get('input_sha256')!=previous:raise ValueError('Layer input provenance mismatch')
        result=layer.get('unpack_result')
        if not isinstance(result,dict) or type(result.get('success')) is not bool:raise ValueError('Invalid unpack result')
        if not isinstance(result.get('warnings'),list) or any(not isinstance(v,str) for v in result['warnings']):raise ValueError('Invalid warnings')
        value=layer.get('output_path')
        if value!=result.get('output_path'):raise ValueError('Contradictory output paths')
        if value is None:
            if result['success'] or layer.get('output_sha256') is not None:raise ValueError('Success without artifact')
            previous=None;continue
        p=artifact_path(value,output)
        if not 0<p.stat().st_size<=max_artifact_bytes:raise ValueError('Artifact exceeds size limit')
        digest=_sha(p)
        if layer.get('output_sha256')!=digest:raise ValueError('Output hash mismatch')
        meta=result.get('metadata')
        if not isinstance(meta,dict):raise ValueError('Invalid result metadata')
        if meta.get('output_sha256',digest)!=digest or meta.get('input_sha256',previous)!=previous:raise ValueError('Metadata hash mismatch')
        artifacts.append((layer,p));previous=digest
    final=report.get('final_path')
    if final is not None:
        if not layers or final!=layers[-1].get('output_path'):raise ValueError('Final artifact mismatch')
        artifact_path(final,output)
    if report['status'] in {'extracted','extracted_vendor_format','extracted_unverified','extracted_with_residual_evidence'} and (not final or not layers[-1]['unpack_result']['success']):raise ValueError('Contradictory successful outcome')
    if report['status']=='no_packing_evidence' and (layers or final):raise ValueError('Invalid no-packing outcome')
    return artifacts

def accepted_recovery(report):
    if report.get('status') not in {'extracted','extracted_vendor_format'} or not report.get('final_path') or not report.get('layers'):return False
    result=report['layers'][-1].get('unpack_result',{})
    if result.get('success') is not True or result.get('validation_status') not in QUALITY or result.get('warnings'):return False
    gates=result.get('metadata',{}).get('reconstruction_acceptance',{}).get('gates')
    return gates is None or (isinstance(gates,dict) and bool(gates) and all(v is True for v in gates.values()))

def validation_payload():
    """Runs in a fresh networkless namespace, never in the analysis worker."""
    from unpacker.types import UnpackOptions
    from unpacker.validation import _validate_artifact_in_process
    kind=sys.argv[1]
    if not re.fullmatch('[a-z_]{1,64}',kind):raise ValueError('Invalid artifact kind')
    extra={'reference':'/reference.bin'} if sys.argv[2]=='1' else {}
    options=UnpackOptions(Path('/'),timeout_seconds=10,max_output_size_mb=32,max_input_size_mb=32,extra=extra)
    print(json.dumps(_validate_artifact_in_process(Path('/source.bin'),Path('/input.bin'),options,kind)))

def verify_artifacts(report,artifacts,sample,reference,output,deadline,*,bubblewrap=None):
    from unpacker.sandbox_cli import build_command
    from unpacker.process import run_command
    original=Path(sample);checks=[]
    for layer,path in artifacts:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('Independent validation deadline exceeded')
        result=layer['unpack_result'];kind=result.get('artifact_kind') or 'reconstructed_pe'
        ref=reference if layer is report['layers'][-1] else None
        code="import sys;sys.path.insert(0,'/app');from unpacker.report_integrity import validation_payload;validation_payload()"
        command=build_command(path,output,[],reference=ref,max_total_output_mb=1,
            payload_code=code,payload_arguments=[kind,'1' if ref else '0'],validation_source=original,bubblewrap=bubblewrap)
        process=run_command(command,timeout=min(10,remaining),max_output_mb=1)
        if process['returncode']!=0 or process['timed_out']:raise ValueError('Independent validation worker failed')
        try:
            response=_load_json(process['stdout'])
            if not isinstance(response,list) or len(response)!=2:raise ValueError('Invalid response shape')
            state,facts=response
        except (ValueError,TypeError):raise ValueError('Invalid independent validation response')
        if state not in QUALITY|{'invalid','partial'} or not isinstance(facts,dict):raise ValueError('Invalid validation state')
        if facts.get('output_sha256')!=layer['output_sha256']:raise ValueError('Independent hash mismatch')
        checks.append({'path':layer['output_path'],'sha256':layer['output_sha256'],'validation_status':state,'gates':facts.get('reconstruction_acceptance',{}).get('gates')})
        result['metadata'].update(facts);result['validation_status']=state
        if state in {'invalid','partial'}:
            result.update(success=False,status='partial' if state=='partial' else 'failed',error=result.get('error') or facts.get('reason'))
            report.update(status=result['status'],error=result['error'],stop_reason='independent_validation_rejected')
        elif layer is report['layers'][-1] and result['success'] and not result.get('warnings'):
            if state=='known_answer_verified':report['status']='extracted'
            elif state=='vendor_validated':report['status']='extracted_vendor_format'
        original=path
    return {'schema':'1','verified_artifacts':checks,'reference_visible_to_analysis_worker':False,
            'validation_boundary':'separate_networkless_namespace','accepted_recovery':accepted_recovery(report)}
