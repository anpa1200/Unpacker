"""Offline release-track contracts;only generated non-executable fixture data."""
from pathlib import Path
import gzip,json,os,struct,subprocess,sys
import pytest


def test_non_ai_cli_never_loads_ai_or_cloud_packages(tmp_path):
    # ELF metadata and one non-executable readonly segment,no entry instructions.
    elf=b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0,64,0,0,64,56,1,64,0,0)
    elf+=struct.pack('<IIQQQQQQ',1,4,0,0x400000,0x400000,120,120,4096)
    original=tmp_path/'original.data';original.write_bytes(elf)
    sample=tmp_path/'wrapper.data';sample.write_bytes(b'#!/bin/sh\n# tail gzip fixture,never executed\n'+gzip.compress(elf,mtime=0))
    code='''import sys,json
class NoAI:
 def find_spec(self,fullname,path=None,target=None):
  if fullname.startswith('unpacker.ai')or fullname.split('.')[0]in {'pydantic','dotenv','openai','anthropic','google'}:raise AssertionError('Core imported optional AI dependency')
sys.meta_path.insert(0,NoAI())
def audit(event,args):
 if event in {'socket.connect','socket.getaddrinfo'}:raise AssertionError('Core attempted network')
sys.addaudithook(audit)
from unpacker.cli import main
raise SystemExit(main())
'''
    env={'PATH':os.defpath,'LANG':'C.UTF-8','HOME':str(tmp_path),'OPENAI_API_KEY':'synthetic-not-a-real-key'}
    p=subprocess.run([sys.executable,'-I','-B','-c',code,str(sample),'-o',str(tmp_path/'output'),'--packer','gzexe','--reference',str(original),'--require-accepted','--json'],capture_output=True,text=True,timeout=20,env=env)
    assert p.returncode==0,p.stderr
    report=json.loads(p.stdout);assert report['status']=='extracted'
    assert Path(report['final_path']).read_bytes()==elf


@pytest.mark.parametrize('options',[[],['--preview']])
def test_ai_is_offline_by_default_even_with_key_and_env_file(options,tmp_path,monkeypatch,capsys):
    pytest.importorskip('pydantic',minversion='2.7')
    from unpacker.ai import cli,config,providers
    evidence=tmp_path/'metadata.json';evidence.write_text(json.dumps({'schema_version':'2','format':'pe','architecture':'x86','parse_status':'parsed','observations':[],'runs':[]}))
    def forbidden(*args,**kwargs):raise AssertionError('Preview loaded credentials or constructed provider')
    monkeypatch.setattr(config.AIConfig,'load',forbidden)
    monkeypatch.setattr(providers,'get_provider',forbidden)
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-not-a-real-key')
    monkeypatch.setattr(sys,'argv',['unpacker-ai',str(evidence),'--env-file',str(tmp_path/'absent.env'),*options])
    assert cli.main()==0
    assert json.loads(capsys.readouterr().out)['schema_version']=='2'


def test_send_and_preview_cannot_be_combined(monkeypatch):
    from unpacker.ai.cli import main
    monkeypatch.setattr(sys,'argv',['unpacker-ai','unused.json','--send','--preview'])
    with pytest.raises(SystemExit)as exc:main()
    assert exc.value.code==2
