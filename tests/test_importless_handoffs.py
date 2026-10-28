"""Generated PE metadata only: rejecting an importless state creates no file."""
from types import SimpleNamespace as N
from pathlib import Path
import pytest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP
from unpacker.guest_export_image import build_export_image
from unpacker.unpackers import _unipacker_shared as shared


def fixture(monkeypatch):
    from unipacker.imagedump import ImportRebuilderDump
    shared.install_unipacker_patch()
    view=build_export_image('user32.dll',['Benign'],0x400000,0x104000)
    uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0x400000,len(view['image']),7);uc.mem_write(0x400000,view['image'])
    uc.reg_write(UC_X86_REG_EIP,view['exports']['Benign'])
    sample=N(_unpacker_generic_handoff=True,original_imports={},dllname_to_functionlist={},allocated_chunks=[],
             loaded_image=view['image'],unpacker=N(name='unknown'))
    dumper=ImportRebuilderDump()
    # This fixture intentionally has no imports. A no-import rebuild result
    # must be rejected before output serialization, regardless of caller.
    monkeypatch.setattr(dumper,'fix_imports',lambda uc,hdr,*args:hdr)
    monkeypatch.setattr(dumper,'fix_sections',lambda *a:pytest.fail('Importless candidate was serialized'))
    monkeypatch.setattr(shared,'_DUMP_STATE',{});monkeypatch.setattr(shared,'_DUMP_WARNINGS',[])
    return uc,sample,dumper,N(ntp={}),view


def test_importless_probe_does_not_write_a_candidate_or_modify_live_guest(tmp_path,monkeypatch):
    uc,sample,dumper,handler,view=fixture(monkeypatch);before=bytes(uc.mem_read(0x400000,len(view['image'])))
    for epoch in range(70):
        sample._unpacker_import_epoch=epoch
        dumper.dump_image(uc,0x400000,len(view['image']),handler,sample,str(tmp_path/'candidate.exe'))
    assert not (tmp_path/'candidate.exe').exists() and not getattr(sample,'_unpacker_rejected_handoffs',[])
    assert shared._DUMP_STATE['skipped_importless_handoffs']==70 and len(sample._unpacker_rejected_keys)==70
    assert uc.mem_read(0x400000,len(view['image']))==before and not sample._unpacker_dump_started


def test_present_directory_with_only_a_null_descriptor_is_also_importless(tmp_path,monkeypatch):
    uc,sample,dumper,handler,view=fixture(monkeypatch)
    def empty_table(uc,hdr,*args):
        hdr.data_directories[1].VirtualAddress=0x1800;hdr.data_directories[1].Size=20
        return hdr
    monkeypatch.setattr(dumper,'fix_imports',empty_table)
    dumper.dump_image(uc,0x400000,len(view['image']),handler,sample,str(tmp_path/'candidate.exe'))
    assert not (tmp_path/'candidate.exe').exists() and shared._DUMP_STATE['skipped_importless_handoffs']==1


def test_importless_probe_retains_the_existing_key_budget(tmp_path,monkeypatch):
    uc,sample,dumper,handler,view=fixture(monkeypatch)
    sample._unpacker_rejected_keys={(i,0,0) for i in range(1024)}
    sample._unpacker_import_epoch=9999
    with pytest.raises(ValueError,match='key budget'):
        dumper.dump_image(uc,0x400000,len(view['image']),handler,sample,str(tmp_path/'candidate.exe'))
    assert not (tmp_path/'candidate.exe').exists()


def test_actual_candidate_rejection_budget_is_not_increased(tmp_path,monkeypatch):
    uc,sample,dumper,handler,view=fixture(monkeypatch);sample._unpacker_rejected_handoffs=[0x401000]*64
    with pytest.raises(ValueError,match='candidate budget'):
        dumper.dump_image(uc,0x400000,len(view['image']),handler,sample,str(tmp_path/'candidate.exe'))
