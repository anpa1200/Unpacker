"""Local-build identity checks must not hide public upstream advisories."""
import hashlib,json,runpy,zipfile
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
resolve=runpy.run_path(str(ROOT/'scripts/owned_dependency.py'))['resolve_queries']
verdict=runpy.run_path(str(ROOT/'scripts/check_dependency_advisories.py'))['verdict']
NAME='unicorn-unipacker';VERSION='1.0.3b7+unpacker.1'


def fixture(tmp_path):
    wheel=tmp_path/'unicorn_unipacker-1.0.3b7+unpacker.1-py3-none-linux_x86_64.whl'
    core=b'benign metadata fixture, never loaded';digest=hashlib.sha256(core).hexdigest();commit='a'*40;source_sha='b'*64
    source={'local_version':VERSION,'upstream_public_version':'1.0.3b7','source_commit':commit,'upstream_source_archive_sha256':source_sha,'native_core':{'sha256':digest}}
    dist='unicorn_unipacker-'+VERSION+'.dist-info'
    with zipfile.ZipFile(wheel,'w') as z:
        z.writestr('unicorn/lib/libunicorn.so',core)
        z.writestr(dist+'/METADATA','Metadata-Version: 2.1\nName: '+NAME+'\nVersion: '+VERSION+'\n')
        z.writestr(dist+'/UPSTREAM-PROVENANCE.json',json.dumps(source))
    entry={'name':NAME,'version':VERSION,'upstream_version':'1.0.3b7','wheel_filename':wheel.name,'wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest(),'source_commit':commit,'source_archive_sha256':source_sha,'native_member':'unicorn/lib/libunicorn.so','native_sha256':digest}
    p=tmp_path/'provenance.json';p.write_text(json.dumps({'schema':'unpacker.owned-dependencies/1','dependencies':[entry]}))
    return p,wheel,entry


def test_reviewed_local_build_queries_only_public_version(tmp_path):
    p,wheel,_=fixture(tmp_path);rows=resolve([(NAME,VERSION)],p,tmp_path)
    assert rows[0]['public_version']=='1.0.3b7' and rows[0]['version']==VERSION
    assert rows[0]['owned_build']['advisory_policy'].endswith('no waiver')


def test_local_version_without_provenance_fails_before_query():
    with pytest.raises(ValueError):resolve([(NAME,VERSION)])


def test_changed_owned_wheel_is_rejected(tmp_path):
    p,wheel,_=fixture(tmp_path);wheel.write_bytes(wheel.read_bytes()+b'changed')
    with pytest.raises(ValueError,match='hash mismatch'):resolve([(NAME,VERSION)],p,tmp_path)


@pytest.mark.parametrize('field,value',[('source_commit','c'*40),('upstream_version','1.0.2')])
def test_false_source_identity_is_rejected(tmp_path,field,value):
    p,wheel,entry=fixture(tmp_path);d=json.loads(p.read_text());d['dependencies'][0][field]=value;p.write_text(json.dumps(d))
    with pytest.raises(ValueError):resolve([(NAME,VERSION)],p,tmp_path)


def test_unlisted_local_package_fails_closed(tmp_path):
    p,_,_=fixture(tmp_path)
    with pytest.raises(ValueError):resolve([('another-local','1.0+unpacker.1')],p,tmp_path)


def test_owned_build_marker_never_suppresses_upstream_advisory():
    row={'name':NAME,'version':VERSION,'queried_public_version':'1.0.3b7','status':'queried','owned_build':{'reviewed':True},'vulnerabilities':[{'id':'SYNTHETIC-UPSTREAM-ADVISORY','withdrawn':None}]}
    assert verdict([row])==1


def test_public_dependency_needs_no_owned_mapping():
    assert resolve([('setuptools','84.1.0')])==[{'name':'setuptools','version':'84.1.0','public_version':'84.1.0'}]
