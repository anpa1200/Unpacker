"""Resolve reviewed local builds to their public upstream advisory identity.

Never sends local version identifiers, code, paths or build metadata to PyPI.
This mapping does not suppress any upstream advisory or prove full security.
"""
import hashlib,json,re,zipfile
from email.parser import BytesParser
from pathlib import Path
from packaging.utils import canonicalize_name,parse_wheel_filename
from packaging.version import Version

def resolve_queries(pairs,provenance=None,wheelhouse=None):
    local=[(n,v) for n,v in pairs if Version(v).local is not None]
    if not local:return [{'name':n,'version':v,'public_version':v} for n,v in pairs]
    if provenance is None or wheelhouse is None:raise ValueError('Local dependency requires reviewed provenance and wheelhouse')
    p=Path(provenance)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>262144:raise ValueError('Invalid provenance file')
    data=json.loads(p.read_text())
    if data.get('schema')!='unpacker.owned-dependencies/1' or not isinstance(data.get('dependencies'),list):raise ValueError('Unknown provenance schema')
    entries={}
    for item in data['dependencies']:
        key=(canonicalize_name(item['name']),item['version'])
        if key in entries:raise ValueError('Duplicate owned dependency')
        entries[key]=item
    result=[]
    for name,version in pairs:
        if Version(version).local is None:
            result.append({'name':name,'version':version,'public_version':version});continue
        item=entries.get((canonicalize_name(name),version))
        if item is None or not Version(version).local.startswith('unpacker.'):raise ValueError('Unreviewed local dependency')
        upstream=item['upstream_version']
        if Version(upstream).local is not None or Version(upstream).public!=Version(version).public:raise ValueError('Upstream version mismatch')
        filename=item['wheel_filename']
        if Path(filename).name!=filename:raise ValueError('Wheel path traversal')
        wheel=Path(wheelhouse)/filename
        if wheel.is_symlink() or not wheel.is_file() or wheel.stat().st_size>67108864:raise ValueError('Invalid owned wheel')
        raw=wheel.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=item['wheel_sha256']:raise ValueError('Owned wheel hash mismatch')
        wheel_name,wheel_version,_,_=parse_wheel_filename(filename)
        if canonicalize_name(wheel_name)!=canonicalize_name(name) or str(wheel_version)!=version:raise ValueError('Wheel identity mismatch')
        with zipfile.ZipFile(wheel) as z:
            names=z.namelist()
            if len(names)!=len(set(names)) or len(names)>2048 or sum(m.file_size for m in z.infolist())>134217728:raise ValueError('Invalid wheel structure')
            metas=[n for n in names if n.endswith('.dist-info/METADATA')]
            records=[n for n in names if n.endswith('.dist-info/UPSTREAM-PROVENANCE.json')]
            if len(metas)!=1 or len(records)!=1:raise ValueError('Missing owned metadata')
            m=BytesParser().parsebytes(z.read(metas[0]));source=json.loads(z.read(records[0]))
            if m.get_all('Name')!=[name] or m.get_all('Version')!=[version]:raise ValueError('Metadata identity mismatch')
            if source.get('local_version')!=version or source.get('upstream_public_version')!=upstream or source.get('source_commit')!=item['source_commit'] or source.get('upstream_source_archive_sha256')!=item['source_archive_sha256']:raise ValueError('Source provenance mismatch')
            member=item['native_member'];info=z.getinfo(member)
            if info.file_size>33554432:raise ValueError('Native member exceeds bound')
            digest=hashlib.sha256(z.read(member)).hexdigest()
            if digest!=item['native_sha256'] or source.get('native_core',{}).get('sha256')!=digest:raise ValueError('Native core hash mismatch')
        result.append({'name':name,'version':version,'public_version':upstream,'owned_build':{'wheel_sha256':item['wheel_sha256'],'native_sha256':item['native_sha256'],'source_commit':item['source_commit'],'advisory_policy':'all public upstream findings retained; no waiver'}})
    return result
