"""Fail release validation on active PyPI-reported advisories or missing evidence.

This is a limited registry advisory gate, not exploitability analysis or a
complete security audit. Only public dependency names/versions are queried.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import urllib.parse
import urllib.request


def verdict(rows):
    if not isinstance(rows,list) or not rows:return 2
    active=False
    for row in rows:
        if not isinstance(row,dict) or row.get('status')!='queried':return 2
        values=row.get('vulnerabilities')
        if not isinstance(values,list) or any(not isinstance(v,dict) or not isinstance(v.get('id'),str) for v in values):return 2
        active=active or any(not v.get('withdrawn') for v in values)
    return 1 if active else 0


def fetch(pair):
    name,version=pair
    url='https://pypi.org/pypi/'+urllib.parse.quote(name,safe='')+'/'+urllib.parse.quote(version,safe='')+'/json'
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(urllib.request.Request(url,headers={'User-Agent':'Unpacker-release-validation'}),timeout=10) as response:
            raw=response.read(4*1024*1024+1)
        if len(raw)>4*1024*1024:raise ValueError('Registry response exceeds bound')
        data=json.loads(raw)
        return {'name':name,'version':version,'source':url,'status':'queried','vulnerabilities':data['vulnerabilities']}
    except Exception as exc:
        return {'name':name,'version':version,'source':url,'status':'unavailable','error_type':type(exc).__name__}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--requirements',type=Path)
    p.add_argument('--snapshot',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--owned-provenance',type=Path)
    p.add_argument('--owned-wheelhouse',type=Path)
    args=p.parse_args()
    if (args.requirements is None)==(args.snapshot is None):p.error('Choose exactly one input')
    if args.snapshot:
        rows=json.loads(args.snapshot.read_text())['dependencies']
    else:
        from packaging.requirements import Requirement
        pairs=[]
        for line in args.requirements.read_text().splitlines():
            text=line.split('#',1)[0].strip()
            if not text:continue
            req=Requirement(text.split(' --hash=',1)[0]);spec=list(req.specifier)
            if req.url or req.marker or req.extras or len(spec)!=1 or spec[0].operator!='==':
                raise ValueError('Explicit version-only requirements required')
            pairs.append((req.name,spec[0].version))
        if not 1<=len(pairs)<=200:raise ValueError('Dependency count outside bound')
        import runpy
        resolve=runpy.run_path(str(Path(__file__).with_name('owned_dependency.py')))['resolve_queries']
        resolved=resolve(pairs,args.owned_provenance,args.owned_wheelhouse)
        with ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(fetch,[(r['name'],r['public_version']) for r in resolved]))
        for row,identity in zip(rows,resolved):
            row['queried_public_version']=row['version'];row['version']=identity['version']
            if 'owned_build' in identity:row['owned_build']=identity['owned_build']
    status=verdict(rows)
    record={'exit_status':status,'scope':'PyPI-reported advisories; no exploitability or completeness claim','dependencies':rows}
    with args.output.open('x') as stream:json.dump(record,stream,indent=2)
    print(json.dumps({'exit_status':status,'packages_with_active_advisories':[
        row.get('name') for row in rows if any(not v.get('withdrawn') for v in row.get('vulnerabilities',[]) if isinstance(v,dict))]}))
    return status


if __name__=='__main__':raise SystemExit(main())
