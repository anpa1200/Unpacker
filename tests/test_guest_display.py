"""Synthetic screen state and explicitly selected guest dialog input."""
import struct
from pathlib import Path
import pytest
from test_winapi_model import fixture_model
from unpacker.winapi_model import UnsupportedAPI


def test_screen_context_lifetime_capabilities_and_metrics_are_consistent():
    model,uc,_=fixture_model();display=model.display
    dc=display.get_dc(uc,0)
    assert dc and display.device_caps(uc,dc,2)==1
    assert display.device_caps(uc,dc,8)==model.system_metrics(uc,0)==1920
    assert display.device_caps(uc,dc,10)==model.system_metrics(uc,1)==1080
    assert display.device_caps(uc,dc,12)==32 and display.device_caps(uc,dc,14)==1
    assert display.device_caps(uc,dc,88)==display.device_caps(uc,dc,90)==96
    assert display.release_dc(uc,1,dc)==0 and dc in display.contexts
    assert display.release_dc(uc,0,dc)==1 and display.release_dc(uc,0,dc)==0
    with pytest.raises(UnsupportedAPI,match='released'):display.device_caps(uc,dc,12)


def test_screen_profile_rejects_unmodeled_windows_caps_and_exhaustion(monkeypatch):
    model,uc,_=fixture_model();display=model.display
    with pytest.raises(UnsupportedAPI,match='window objects'):display.get_dc(uc,123)
    dc=display.get_dc(uc,0)
    with pytest.raises(UnsupportedAPI,match='outside'):display.device_caps(uc,dc,999)
    monkeypatch.setattr(display,'MAX_DCS',1)
    before=dict(display.contexts)
    with pytest.raises(UnsupportedAPI,match='budget'):display.get_dc(uc,0)
    assert display.contexts==before


def test_gdi_dispatch_uses_actual_handle_and_stdcall_return():
    model,uc,_=fixture_model();model.install({})
    uc.mem_write(0x100,struct.pack('<II',0x401234,0))
    dc,esp=model.handler.apicall(0,'GetDC',uc,0x100,False)
    assert esp==0x104 and uc.mem_read(esp,4)==struct.pack('<I',0x401234)
    uc.mem_write(0x200,struct.pack('<III',0x401678,dc,12))
    result,esp=model.handler.apicall(0,'GetDeviceCaps',uc,0x200,False)
    assert (result,esp)==(32,0x208)
    uc.mem_write(0x300,struct.pack('<III',0x401abc,0,dc))
    assert model.handler.apicall(0,'ReleaseDC',uc,0x300,False)==(1,0x308)


@pytest.mark.parametrize('choice,answer',[('no',7),('yes',6)])
def test_yesno_policy_is_explicit_recorded_and_does_not_change_other_dialogs(choice,answer):
    model,uc,_=fixture_model();model.yesno_answer=choice
    assert model.message(uc,0,0,0,4)==answer
    assert model.events[-1]['response']==answer
    assert 'MessageBox response selected by noninteractive model' in model.warnings
    assert model.message(uc,0,0,0,3)==2  # YES/NO/CANCEL still selects Cancel.
    assert model.message(uc,0,0,0,0)==1


@pytest.mark.parametrize('bad',[None,False,{},[],7,'maybe'])
def test_invalid_yesno_policy_is_rejected_before_analysis(tmp_path,bad):
    from unpacker.orchestrator import run
    assert run(tmp_path/'not-read',tmp_path/'out',guest_yesno_answer=bad).status=='input_error'


def test_cli_policies_default_no_and_require_explicit_yes():
    from unpacker.cli import build_parser as direct
    from unpacker.sandbox_cli import build_parser as isolated
    for parser in (direct(),isolated()):
        assert parser.parse_args(['fixture']).guest_yesno_answer=='no'
        assert parser.parse_args(['fixture','--guest-yesno-answer','yes']).guest_yesno_answer=='yes'
        with pytest.raises(SystemExit):parser.parse_args(['fixture','--guest-yesno-answer','arbitrary'])


def test_orchestrator_forwards_validated_policy_without_execution(tmp_path,monkeypatch):
    import unpacker.orchestrator as module
    from unpacker.types import DetectionResult,UnpackResult
    sample=tmp_path/'fixture';sample.write_bytes(b'benign')
    class Pipeline:
        def __init__(self,**_):pass
        def detect(self,_):return DetectionResult(format='pe')
    captured=[]
    def attempt(path,backend,options):
        captured.append(options.extra['guest_yesno_answer'])
        return UnpackResult(False,status='unsupported',error='synthetic stop')
    monkeypatch.setattr(module,'DetectorPipeline',Pipeline)
    monkeypatch.setattr(module,'unpack_with_dispatcher',attempt)
    result=module.run(sample,tmp_path/'out',packer_id='fixture',guest_yesno_answer='yes')
    assert result.status=='unsupported' and captured==['yes']
