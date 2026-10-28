"""Synthetic regression cases for integrity, detection and bounded execution."""
import io,json,sys,time,zipfile,runpy
from pathlib import Path
from types import SimpleNamespace as N
import pytest
from unpacker.types import DetectionResult,PackerMatch,UnpackOptions,UnpackResult
from unpacker.detector.pipeline import DetectorPipeline,_merge_results
from unpacker.unpackers import unpack_with_dispatcher
from unpacker.orchestrator import run
from unpacker.process import run_command


def test_path_labels_neither_create_nor_downgrade_evidence():
    assert not _merge_results([], .99, Path('/vmprotect/themida/x')).is_packed
    r=_merge_results([DetectionResult(matches=[PackerMatch('vmprotect',.95,'sections'),PackerMatch('vmprotect',.8,'signature')])],.5,Path('/vmprotect/x'))
    assert r.best_match.confidence==.95 and len(r.matches)==2


def test_native_upx_validates_unsupported_outer_format(tmp_path,monkeypatch):
    import unpacker.process
    import shutil
    p=tmp_path/'neutral.bin';p.write_bytes(b'not a PE: UPX!')
    monkeypatch.setattr(shutil,'which',lambda tool:sys.executable)
    monkeypatch.setattr(unpacker.process,'run_command',lambda *a,**k:dict(returncode=0,timed_out=False))
    r=DetectorPipeline()._detect_in_process(p)
    assert r.best_packer_id=='upx' and r.status=='native_format'
    monkeypatch.setattr(unpacker.process,'run_command',lambda *a,**k:dict(returncode=2,timed_out=False))
    r=DetectorPipeline()._detect_in_process(p)
    assert not r.is_packed and r.status=='unsupported_format'


def test_invalid_or_plain_input_never_claims_not_packed_success(tmp_path):
    p=tmp_path/'plain.bin';p.write_text('plain text')
    r=run(p,tmp_path/'out')
    assert r.status=='unsupported_format' and r.final_path is None and r.error
    p.write_bytes(b'MZ'+b'\0'*64)
    assert DetectorPipeline().detect(p).status=='parse_error'


def test_method_failure_is_preserved(tmp_path):
    p=tmp_path/'file';p.write_bytes(b'MZ')
    class Broken:
        name='broken'
        def detect(self,*a,**k):raise ValueError('fixture')
    pipeline=DetectorPipeline(use_native_upx=False)
    pipeline._methods=[Broken()]
    r=pipeline.detect(p,pe=object())
    assert r.status=='inconclusive' and r.errors


@pytest.mark.parametrize('budget',[0,-1,33])
def test_layer_budget_is_validated(tmp_path,budget):
    p=tmp_path/'input';p.write_bytes(b'fixture')
    assert run(p,tmp_path/'out',max_layers=budget).status=='input_error'


@pytest.mark.parametrize('bad',[float('nan'),float('inf'),-1])
def test_detector_threshold_validation(bad):
    with pytest.raises(ValueError):DetectorPipeline(confidence_threshold=bad)


def test_dispatcher_rejects_stale_unrelated_and_empty_outputs(tmp_path,monkeypatch):
    import unpacker.unpackers as dispatcher
    sample=tmp_path/'sample';sample.write_bytes(b'input')
    stale=tmp_path/'old.unpacked.bin';stale.write_bytes(b'old')
    dirs=[]
    class Fake:
        def unpack(self,path,opts):
            dirs.append(opts.output_dir)
            return UnpackResult(True,output_path=stale)
    monkeypatch.setattr(dispatcher,'get_unpacker_for',lambda *a:Fake())
    for _ in range(2):
        r=unpack_with_dispatcher(sample,'x',UnpackOptions(tmp_path/'out'))
        assert not r.success and r.output_path is None
    assert dirs[0]!=dirs[1] and stale.read_bytes()==b'old'
    class Empty:
        def unpack(self,path,opts):
            out=opts.output_dir/'empty.bin';out.touch()
            return UnpackResult(True,output_path=out)
    monkeypatch.setattr(dispatcher,'get_unpacker_for',lambda *a:Empty())
    assert not unpack_with_dispatcher(sample,'x',UnpackOptions(tmp_path/'out')).success


def test_backend_initialization_exception_does_not_escape(tmp_path,monkeypatch):
    import unpacker.unpackers as dispatcher
    p=tmp_path/'sample';p.write_bytes(b'fixture')
    class Broken:
        def unpack(self,*a):raise AttributeError('DIRECTORY_ENTRY_IMPORT')
    monkeypatch.setattr(dispatcher,'get_unpacker_for',lambda *a:Broken())
    r=unpack_with_dispatcher(p,'x',UnpackOptions(tmp_path/'out'))
    assert r.status=='backend_error' and not r.success


def test_emulation_requires_explicit_opt_in(tmp_path):
    from unpacker.unpackers._unipacker_shared import run_unipacker_emulation
    r=run_unipacker_emulation(tmp_path/'absent',tmp_path/'dump',UnpackOptions(tmp_path))
    assert r.status=='unsupported'


def test_hard_deadline_kills_process_before_late_write(tmp_path):
    late=tmp_path/'late'
    cmd=[sys.executable,'-I','-B','-c',f'import time;time.sleep(1);open({str(late)!r},"w").write("late")']
    r=run_command(cmd,timeout=.1)
    assert r['timed_out']
    time.sleep(.15)
    assert not late.exists()


def test_child_does_not_inherit_api_keys(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','fixture-secret')
    r=run_command([sys.executable,'-I','-B','-c','import os;print("OPENAI_API_KEY" in os.environ)'],timeout=3)
    assert r['returncode']==0 and r['stdout'].strip()=='False'


def test_gzip_wrapper_extracts_without_running_script(tmp_path):
    import gzip
    p=tmp_path/'wrapper';p.write_bytes(b'#!/bin/sh\n# tail gzip\n'+gzip.compress(b'\x7fELF'+b'benign-fixture'))
    assert DetectorPipeline(use_native_upx=False).detect(p).best_packer_id=='gzexe'
    # Direct adapter confirms bounded decompression; dispatcher would reject malformed ELF.
    from unpacker.unpackers.generic import GenericUnpacker
    r=GenericUnpacker().unpack(p,UnpackOptions(tmp_path))
    assert r.success and r.output_path.read_bytes()==b'\x7fELFbenign-fixture'


def test_signature_loader_and_entry_point_offsets(tmp_path):
    from unpacker.detector.signatures import SignatureDetector
    rules=tmp_path/'rules';rules.mkdir()
    (rules/'test.json').write_text(json.dumps([dict(packer_id='fixture',pattern='010203',offset=-1)]))
    p=tmp_path/'sample';p.write_bytes(b'xxxxx\x01\x02\x03')
    pe=N(OPTIONAL_HEADER=N(AddressOfEntryPoint=4096),get_offset_from_rva=lambda r:5)
    assert SignatureDetector(rules).detect(p,pe=pe).best_packer_id=='fixture'


def test_rootfs_parent_resolves_only_matching_arch(tmp_path):
    from unpacker.unpackers._qiling_shared import _find_rootfs
    x=tmp_path/'x8664_windows';(x/'dlls').mkdir(parents=True);(x/'dlls/kernel32.dll').write_bytes(b'fixture')
    assert _find_rootfs('x8664',tmp_path)==x
    assert _find_rootfs('x86',tmp_path) is None


def test_archive_extraction_rejects_traversal_multi_members_and_preserves_name(tmp_path):
    module=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/step0_find_and_download_samples.py'))
    def archive(names):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            for name in names:z.writestr(name,b'benign-text')
        return b.getvalue()
    with pytest.raises(ValueError):module['extract_zip'](archive(['../escape']),tmp_path)
    with pytest.raises(ValueError):module['extract_zip'](archive(['a','b']),tmp_path)
    p=module['extract_zip'](archive(['folder/fixture.txt']),tmp_path)
    assert p.name=='sample.bin' and p.read_bytes()==b'benign-text' and not p.stat().st_mode&0o111


def test_batch_engine_pause_stops_instead_of_waiting(tmp_path,monkeypatch):
    import unpacker.unpackers._unipacker_shared as shared
    import unpacker.detector.format_ as fmt
    pe=N(FILE_HEADER=N(Machine=0x14c),OPTIONAL_HEADER=N(Magic=0x10b),DIRECTORY_ENTRY_IMPORT=[object()],close=lambda:None)
    monkeypatch.setattr(fmt,'load_pe',lambda p:pe)
    monkeypatch.setattr(shared,'unipacker_import_error',lambda:None)
    monkeypatch.setattr(shared,'install_unipacker_patch',lambda:None)
    class Engine:
        def __init__(self,sample,out):self.out=Path(out)
        def register_client(self,client):pass
        def pause(self):raise AssertionError('Interactive wait must not happen')
        def stop(self):self.out.write_bytes(b'benign fake dump')
        def emu(self):self.pause()
    monkeypatch.setitem(sys.modules,'unipacker.core',N(Sample=lambda *a,**k:N(unpacker=N(name='fixture')),UnpackerEngine=Engine,SimpleClient=lambda event:object()))
    r=shared._run_unipacker_in_process(tmp_path/'input',tmp_path/'output',UnpackOptions(tmp_path),'fixture')
    assert r.success and r.output_path.read_bytes()==b'benign fake dump'


def test_config_rejects_unknown_unimplemented_and_wrong_types(tmp_path):
    pytest.importorskip('yaml')
    from unpacker.configuration import load_config
    p=tmp_path/'config.yaml'
    p.write_text('orchestrator:\n  max_layers: 3\n  allow_emulation: false\n')
    assert load_config(p)=={'max_layers':3,'allow_emulation':False}
    for text in ['orchestrator:\n  rebuild_iat: true\n','detector:\n  confidence_threshold: nope\n','orchestrator:\n  allow_emulation: yesplease\n','mystery: {}\n']:
        p.write_text(text)
        with pytest.raises(ValueError):load_config(p)


def test_sandbox_command_has_no_network_or_home_mount(tmp_path,monkeypatch):
    import unpacker.sandbox_cli as sandbox
    monkeypatch.setattr(sandbox.shutil,'which',lambda tool:'/usr/bin/bwrap')
    sample=tmp_path/'sample';sample.write_bytes(b'fixture')
    cmd=sandbox.build_command(sample,tmp_path,[])
    assert '--unshare-all' in cmd and '--clearenv' in cmd and '--cap-drop' in cmd
    assert '--share-net' not in cmd and '/secure/provider.env' not in cmd


def test_vendor_negative_prevents_section_marker_feedback(tmp_path,monkeypatch):
    import unpacker.process
    import shutil
    p=tmp_path/'sample';p.write_bytes(b'\x7fELF UPX! UPX0')
    monkeypatch.setattr(shutil,'which',lambda tool:sys.executable)
    monkeypatch.setattr(unpacker.process,'run_command',lambda *a,**k:dict(returncode=2,timed_out=False,stdout='',stderr='NotPackedException'))
    class Marker:
        def detect(self,*a,**k):return DetectionResult(matches=[PackerMatch('upx',.98,'sections')])
    pipeline=DetectorPipeline();pipeline._methods=[Marker()]
    result=pipeline.detect(p,elf=object())
    assert result.best_packer_id is None


def test_native_dos_output_not_misparsed_as_pe(tmp_path):
    from unpacker.validation import validate_artifact
    source=tmp_path/'input';source.write_bytes(b'fixture-compressed')
    output=tmp_path/'output';output.write_bytes(b'MZ'+b'\0'*100)
    state,facts=validate_artifact(source,output,UnpackOptions(tmp_path),'native_decompressed_file')
    assert state=='vendor_validated' and facts['format']=='vendor_native_non_pe'


def test_vendor_format_completes_without_invalid_second_parse(tmp_path,monkeypatch):
    import unpacker.orchestrator as orchestration
    sample=tmp_path/'input';sample.write_bytes(b'packed fixture')
    output=tmp_path/'native';output.write_bytes(b'MZ-native-DOS')
    class Pipeline:
        def __init__(self,**kwargs):pass
        def detect(self,path):
            assert path==sample,'Do not treat vendor-native output as a malformed PE'
            return DetectionResult(matches=[PackerMatch('upx',1.,'native_integrity')],is_packed=True,status='native_format')
    monkeypatch.setattr(orchestration,'DetectorPipeline',Pipeline)
    monkeypatch.setattr(orchestration,'unpack_with_dispatcher',lambda *a:UnpackResult(True,output_path=output,validation_status='vendor_validated'))
    result=orchestration.run(sample,tmp_path/'out')
    assert result.status=='extracted_vendor_format' and not result.error and len(result.layers)==1


def test_emulator_logs_are_bounded_and_timeout_diagnostics_retained(tmp_path,monkeypatch):
    import unpacker.backend_worker as worker
    captured=io.StringIO();monkeypatch.setattr(sys,'__stderr__',captured)
    log=worker.BoundedLog();log.write('x'*20000);log.write('y'*20000)
    assert len(log.text)==12000 and len(captured.getvalue())==12000
    monkeypatch.setattr(worker,'run_command',lambda *a,**k:dict(timed_out=True,returncode=-9,stdout='',stderr='bounded fixture diagnostic'))
    r=worker.supervise('unipacker',tmp_path/'input',tmp_path/'output',UnpackOptions(tmp_path),'fixture')
    assert r.status=='timeout' and r.log==['bounded fixture diagnostic']


def test_qiling_all_zero_snapshot_is_rejected(tmp_path,monkeypatch):
    import unpacker.detector.format_ as fmt
    from unpacker.unpackers._qiling_shared import _run_qiling_in_process
    pe=N(FILE_HEADER=N(Machine=0x8664),OPTIONAL_HEADER=N(Magic=0x20b,ImageBase=0x400000,SizeOfImage=4096),close=lambda:None)
    monkeypatch.setattr(fmt,'load_pe',lambda p:pe)
    class Qiling:
        def __init__(self,*a,**k):self.loader=N(pe_image_address=0x400000);self.mem=N(read=lambda base,size:b'\0'*size)
        def run(self,**k):pass
        def stop(self):pass
    monkeypatch.setitem(sys.modules,'qiling',N(Qiling=Qiling))
    monkeypatch.setitem(sys.modules,'qiling.const',N(QL_VERBOSE=N(OFF=0)))
    output=tmp_path/'snapshot'
    result=_run_qiling_in_process(tmp_path/'input',output,UnpackOptions(tmp_path,extra={'rootfs':str(tmp_path)}),'fixture')
    assert not result.success and not output.exists()


def test_oversized_output_rejected_before_hashing(tmp_path, monkeypatch):
    import unpacker.validation as validation
    sample=tmp_path/'input';sample.write_bytes(b'input')
    output=tmp_path/'output';output.write_bytes(b'large')
    def forbidden(*args):raise AssertionError('Oversized artifact must not be hashed')
    monkeypatch.setattr(validation,'sha256',forbidden)
    status,facts=validation._validate_artifact_in_process(sample,output,UnpackOptions(tmp_path,max_output_size_mb=0))
    assert status=='invalid' and facts['reason']=='Empty or oversized output'


def test_elf_original_mismatch_is_partial(tmp_path):
    import struct
    from unpacker.validation import validate_artifact
    # Minimal benign ELF64 with one bounded loadable segment.
    data=bytearray(120);data[:16]=b'\x7fELF'+bytes([2,1,1])+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',data,16,2,62,1,0,64,0,0,64,56,1,64,0,0)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x400000,0x400000,120,120,4096)
    sample=tmp_path/'packed';sample.write_bytes(b'packed')
    output=tmp_path/'output';output.write_bytes(data)
    reference=tmp_path/'reference';reference.write_bytes(bytes(data)+b'original')
    status,facts=validate_artifact(sample,output,UnpackOptions(tmp_path,extra={'reference':str(reference)}))
    assert status=='partial' and facts['exact_original_sha256_match'] is False


def test_failed_import_parse_closes_owned_pe(monkeypatch,tmp_path):
    import pefile
    from unpacker.detector.format_ import load_pe
    closed=[]
    class Broken:
        def parse_data_directories(self,**kwargs):raise ValueError('malformed import')
        def close(self):closed.append(True)
    monkeypatch.setattr(pefile,'PE',lambda *a,**k:Broken())
    assert load_pe(tmp_path/'fixture') is None and closed==[True]


def test_process_logs_are_capped():
    result=run_command([sys.executable,'-I','-c','print("x"*100000)'],5)
    assert result['returncode']==0 and len(result['stdout'])==65536


def test_layer_limit_final_parser_failure_is_not_success(tmp_path,monkeypatch):
    import unpacker.orchestrator as orchestrator
    sample=tmp_path/'sample';sample.write_bytes(b'input')
    output=tmp_path/'output';output.write_bytes(b'different output')
    class Pipeline:
        def __init__(self,**kwargs):self.calls=0
        def detect(self,path):
            self.calls+=1
            return DetectionResult(is_packed=True,matches=[PackerMatch('upx',1.,'fixture')]) if self.calls==1 else DetectionResult(status='parse_error')
    monkeypatch.setattr(orchestrator,'DetectorPipeline',Pipeline)
    monkeypatch.setattr(orchestrator,'unpack_with_dispatcher',lambda *args:UnpackResult(True,output_path=output))
    report=orchestrator.run(sample,tmp_path/'out',max_layers=1)
    assert report.status=='partial' and report.stop_reason=='final_detection_inconclusive'
