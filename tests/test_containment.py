"""Benign worker/resource and reconstruction acceptance regressions."""
import json,sys,time
from pathlib import Path
from types import SimpleNamespace as N
import pytest
from unpacker.process import run_command
from unpacker.budget import check_output_budget
from unpacker.types import UnpackOptions,UnpackResult


def test_aggregate_budget_terminates_many_small_files(tmp_path):
    code='''import pathlib,time
p=pathlib.Path.cwd()
for i in range(200):
 (p/str(i)).write_bytes(b'x'*65536)
 time.sleep(.005)
time.sleep(2)
(p/'late').write_text('bad')
'''
    result=run_command([sys.executable,'-I','-c',code],5,cwd=tmp_path,output_root=tmp_path,max_total_output_mb=1)
    assert result['output_limit_exceeded'] and not result['timed_out']
    time.sleep(.1)
    assert not (tmp_path/'late').exists()
    assert len(list(tmp_path.iterdir()))<100


def test_entry_count_limit_and_symlinks_fail_closed(tmp_path):
    for i in range(4):(tmp_path/str(i)).touch()
    assert check_output_budget(tmp_path,1024*1024,max_entries=3)
    link=tmp_path/'link';link.symlink_to('/etc')
    assert check_output_budget(tmp_path,1024*1024,max_entries=100)


def test_dispatcher_budget_includes_retained_layers(tmp_path,monkeypatch):
    import unpacker.unpackers as dispatcher
    sample=tmp_path/'input';sample.write_bytes(b'fixture')
    out=tmp_path/'out';out.mkdir();(out/'old-layer').write_bytes(b'x'*(1024*1024-4096))
    class Backend:
        def unpack(self,sample,options):
            path=options.output_dir/'dump';path.write_bytes(b'x'*8192)
            return UnpackResult(True,output_path=path)
    monkeypatch.setattr(dispatcher,'get_unpacker_for',lambda *args:Backend())
    result=dispatcher.unpack_with_dispatcher(sample,'fixture',UnpackOptions(out,max_total_output_size_mb=1))
    assert result.status=='resource_limit' and not result.success


@pytest.mark.parametrize('operation',['detect','validate'])
def test_static_worker_hard_deadline(operation,tmp_path,monkeypatch):
    import unpacker.static_worker as worker
    original=worker.run_command
    # Replace the child entry point with a trusted deliberately hanging parser.
    def hanging(command,**kwargs):
        return original([sys.executable,'-I','-c','import time;time.sleep(5)'],**kwargs)
    monkeypatch.setattr(worker,'run_command',hanging)
    start=time.monotonic()
    value,error=worker.invoke({'operation':operation},.1)
    assert value is None and 'hard deadline' in error and time.monotonic()-start<2


def test_detector_uses_serialized_worker_settings(tmp_path,monkeypatch):
    from unpacker.detector.pipeline import DetectorPipeline
    import unpacker.static_worker as worker
    payloads=[]
    def fake(payload,timeout):
        payloads.append((payload,timeout));return dict(matches=[],is_packed=False,status='analyzed'),None
    monkeypatch.setattr(worker,'invoke',fake)
    result=DetectorPipeline(use_entropy=False,static_timeout_seconds=.2).detect(tmp_path/'input')
    assert result.status=='analyzed' and payloads[0][0]['settings']['use_entropy'] is False
    assert payloads[0][1]==.2


def pe_fixture(code=b'code',entry=4096,execute=True,imports=('ExitProcess',),machine=332):
    flags=0x40000000|(0x20000000 if execute else 0)
    import struct
    descriptor=struct.pack('<IIIII',0x2100,0,0,0x2400,0x2000)+bytes(20)
    def data(rva,count):
        if 0x2000<=rva<0x2200:return ((0x3000).to_bytes(4,'little')*len(imports)+bytes(4))[(rva%256):(rva%256)+count]
        if 0x2300<=rva<0x2328:return descriptor[rva-0x2300:rva-0x2300+count]
        if 0x2400<=rva<0x240d:return b'KERNEL32.dll\0'[rva-0x2400:rva-0x2400+count]
        return code[rva-4096:rva-4096+count]
    return N(OPTIONAL_HEADER=N(AddressOfEntryPoint=entry,Magic=0x10b,DATA_DIRECTORY=[N(),N(VirtualAddress=0x2300,Size=40)]),FILE_HEADER=N(Machine=machine),
             sections=[N(Characteristics=flags,VirtualAddress=4096,Misc_VirtualSize=len(code),SizeOfRawData=len(code),PointerToRawData=512),
                       N(Characteristics=0x40000000,VirtualAddress=0x2000,Misc_VirtualSize=4096,SizeOfRawData=4096,PointerToRawData=1024)],
             DIRECTORY_ENTRY_IMPORT=[N(dll=b'KERNEL32.dll',struct=N(FirstThunk=0x2000,OriginalFirstThunk=0x2100),imports=[N(name=name.encode(),ordinal=None) for name in imports])],
             get_data=data)


def test_reconstruction_gates_separate_code_mapping_and_imports():
    from unpacker.reconstruction import compare_pe_reference
    original=pe_fixture()
    assert compare_pe_reference(pe_fixture(),original)['passed']
    bad=compare_pe_reference(pe_fixture(execute=False),original)
    assert bad['gates']['executable_bytes'] and bad['gates']['entry_rva'] and not bad['gates']['entry_mapping'] and not bad['passed']
    bad=compare_pe_reference(pe_fixture(imports=()),original)
    assert not bad['gates']['imports'] and bad['missing_imports']==[('kernel32.dll','ExitProcess')]
    assert not compare_pe_reference(pe_fixture(code=b'diff'),original)['gates']['executable_bytes']
    assert not compare_pe_reference(pe_fixture(machine=34404),original)['gates']['machine']


def test_reference_mapping_rejects_entry_in_virtual_zero_fill():
    from unpacker.reconstruction import compare_pe_reference
    candidate=pe_fixture(entry=4100);candidate.sections[0].Misc_VirtualSize=4096
    assert not compare_pe_reference(candidate,pe_fixture())['gates']['entry_mapping']


def test_handoff_execute_repair_is_narrow_and_observable():
    from unpacker.unpackers._unipacker_shared import _mark_handoff_section_executable
    data=N(VirtualAddress=8192,VirtualSize=4096,SizeOfRawData=4096,Characteristics=0xC0000040)
    code=N(VirtualAddress=4096,VirtualSize=4096,SizeOfRawData=4096,Characteristics=0xC0000040)
    hdr=N(opt_header=N(AddressOfEntryPoint=4200),section_list=[code,data])
    assert _mark_handoff_section_executable(hdr)
    assert code.Characteristics&0x20000000 and not data.Characteristics&0x20000000
    assert not _mark_handoff_section_executable(hdr)


def test_evidence_export_rejects_links_traversal_duplicates_and_budget(tmp_path):
    import io,tarfile
    from unpacker.evidence_archive import unpack_evidence
    def make(entries):
        path=tmp_path/'export.tar'
        with tarfile.open(path,'w') as archive:
            for name,kind,size in entries:
                item=tarfile.TarInfo(name);item.type=kind;item.size=size
                if kind==tarfile.SYMTYPE:item.linkname='/etc/passwd';item.size=0
                archive.addfile(item,io.BytesIO(b'x'*size) if item.isfile() else None)
        return path
    for entries in [[('../bad',tarfile.REGTYPE,1)],[('link',tarfile.SYMTYPE,0)],[('same',tarfile.REGTYPE,1),('same',tarfile.REGTYPE,1)],[('file/child',tarfile.REGTYPE,1),('file',tarfile.REGTYPE,1)]]:
        out=tmp_path/'out';out.mkdir(exist_ok=True)
        with pytest.raises(ValueError):unpack_evidence(make(entries),out,1024*1024)
        assert not list(out.iterdir())
    with pytest.raises(ValueError):unpack_evidence(make([('large',tarfile.REGTYPE,5000)]),out,4096)
    result=unpack_evidence(make([('nested/fixture',tarfile.REGTYPE,5)]),out,4096)
    assert result['files']==1 and (out/'nested/fixture').read_bytes()==b'xxxxx'
    assert (out/'nested/fixture').stat().st_mode&0o777==0o600


def test_process_can_stream_bounded_archive_without_log_read(tmp_path):
    output=tmp_path/'bytes'
    result=run_command([sys.executable,'-I','-c','import sys;sys.stdout.buffer.write(b"x"*100000)'],3,stdout_file=output)
    assert result['returncode']==0 and output.stat().st_size==100000 and result['stdout']==''


def test_sandbox_output_uses_capacity_limited_private_mount(tmp_path,monkeypatch):
    import unpacker.sandbox_cli as sandbox
    monkeypatch.setattr(sandbox.shutil,'which',lambda tool:'/usr/bin/bwrap')
    command=sandbox.build_command(tmp_path/'sample',tmp_path,[],max_total_output_mb=7)
    index=command.index('/out')
    assert command[index-3:index+1]==['--size',str(7*1024*1024),'--tmpfs','/out']
    assert str(tmp_path.resolve()) not in command


def test_failed_static_validation_cannot_expose_unchecked_artifact(tmp_path,monkeypatch):
    import unpacker.static_worker as worker
    import unpacker.unpackers as dispatcher
    sample=tmp_path/'input';sample.write_bytes(b'input')
    class Backend:
        def unpack(self,sample,options):
            output=options.output_dir/'dump';output.write_bytes(b'benign unchecked bytes')
            return UnpackResult(True,output_path=output)
    monkeypatch.setattr(dispatcher,'get_unpacker_for',lambda *args:Backend())
    monkeypatch.setattr(worker,'invoke',lambda *args:(None,'Static analysis hard deadline exceeded'))
    result=dispatcher.unpack_with_dispatcher(sample,'fixture',UnpackOptions(tmp_path/'out'))
    assert not result.success and result.status=='timeout' and result.output_path is None
