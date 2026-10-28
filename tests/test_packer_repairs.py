"""Benign strict import-table and packer-layout regression tests."""
import struct
from types import SimpleNamespace as N
import pytest
from unpacker.pe_rebuilder.imports import retained_import_table,file_backed_data


def imports_fixture():
    data=bytearray(4096)
    struct.pack_into('<IIIII',data,0,0x1100,0,0,0x1200,0x1140)
    struct.pack_into('<III',data,0x100,0x1300,0x80000007,0)
    struct.pack_into('<III',data,0x140,0x1300,0x80000007,0)
    data[0x200:0x20d]=b'KERNEL32.dll\0'
    data[0x300:0x30e]=b'\0\0ExitProcess\0'
    section=N(VirtualAddress=0x1000,Misc_VirtualSize=4096,SizeOfRawData=4096)
    pe=N(OPTIONAL_HEADER=N(Magic=0x10b),FILE_HEADER=N(Machine=0x14c),get_data=lambda rva,count:bytes(data[rva-0x1000:rva-0x1000+count]))
    return pe,[section],data


def test_retained_imports_validate_name_ordinal_and_terminator():
    pe,sections,data=imports_fixture();table=retained_import_table(pe,0x1000,sections)
    assert table['symbol_count']==2 and table['descriptor_bytes']==40
    assert table['descriptors'][0]['symbols']==['ExitProcess','#7']


@pytest.mark.parametrize('mutation',['module','name','ordinal','iat','bound','empty'])
def test_retained_imports_reject_malformed_tables(mutation):
    pe,sections,data=imports_fixture()
    if mutation=='module':data[0x200]=0xff
    if mutation=='name':struct.pack_into('<I',data,0x100,0xdeadbeef)
    if mutation=='ordinal':struct.pack_into('<I',data,0x100,0x80010001)
    if mutation=='iat':struct.pack_into('<I',data,16,0xffff0000)
    if mutation=='bound':sections[0].SizeOfRawData=16
    if mutation=='empty':data[:20]=bytes(20)
    with pytest.raises(ValueError):retained_import_table(pe,0x1000,sections)


def test_retained_imports_bound_symbol_count():
    pe,sections,data=imports_fixture()
    with pytest.raises(ValueError):retained_import_table(pe,0x1000,sections,max_symbols=1)


def test_retained_rva_mapping_rejects_overlaps_and_zero_fill():
    pe,sections,data=imports_fixture()
    with pytest.raises(ValueError):file_backed_data(pe,0x1000,1,sections*2)
    sections[0].SizeOfRawData=32
    with pytest.raises(ValueError):file_backed_data(pe,0x1100,4,sections)


def test_generic_handoff_starts_with_bounded_original_section(tmp_path,monkeypatch):
    import sys
    from unpacker.unpackers._unipacker_shared import _configure_generic_unpacker
    marker=object();monkeypatch.setitem(sys.modules,'unipacker.imagedump',N(ImportRebuilderDump=lambda:marker))
    unpacker=N(name='unknown',allowed_sections=['stub'])
    sample=N(unpacker=unpacker,opt_header=N(ImageBase=0x400000),sections=[N(Name='stub',VirtualAddress=0x2000,VirtualSize=0x1000,SizeOfRawData=0x1000),N(Name='code',VirtualAddress=0x1000,VirtualSize=0x1000,SizeOfRawData=0)])
    assert _configure_generic_unpacker(sample)
    assert unpacker.allowed_addr_ranges==[(0x402000,0x402fff)] and unpacker.write_execute_control
    assert unpacker.dumper is marker
    unpacker.name='FSG';assert not _configure_generic_unpacker(sample)


def test_image_dump_span_stops_at_unmapped_holes_and_joins_adjacent_regions():
    import unpacker.unpackers._unipacker_shared as shared
    uc=N(mem_regions=lambda:[(0,0xfff,7),(0x400000,0x400fff,7),(0x401000,0x401fff,5),(0x500000,0x50ffff,7)])
    assert shared._contiguous_image_span(uc,0x400000)==8192
    with pytest.raises(ValueError):shared._contiguous_image_span(uc,0x300000)
    uc.mem_regions=lambda:[(0x400000,0x400000+shared._MAX_DUMP_BYTES,7)]
    with pytest.raises(ValueError):shared._contiguous_image_span(uc,0x400000)


def test_generic_handoff_ignores_stub_hops_selfmod_and_non_image_addresses():
    from unpacker.unpackers._unipacker_shared import _generic_handoff_eligible
    unpacker=N(_handoff_image_sections=[(0x401000,0x12000,116),(0x413000,0x6000,0x4800)],_handoff_loader_sections=set())
    assert not _generic_handoff_eligible(unpacker,0x40101b,[],False)
    assert not _generic_handoff_eligible(unpacker,0x413024,[],False)
    assert not _generic_handoff_eligible(unpacker,0x413100,[(0x413100,0x413110)],True)
    assert _generic_handoff_eligible(unpacker,0x40532c,[(0x401000,0x412fff)],True)
    assert not _generic_handoff_eligible(unpacker,0x100000,[],True)


@pytest.mark.parametrize('resolved',[False,True])
@pytest.mark.parametrize('offset,expected',[(0,False),(115,False),(116,True),(0x1000,True)])
def test_classified_loader_keeps_raw_boundary_without_rescanning_writes(resolved,offset,expected):
    from unpacker.unpackers._unipacker_shared import _generic_handoff_eligible
    class Unscannable:
        def __iter__(self):raise AssertionError('Known loader does not need write lookup')
    unpacker=N(_handoff_image_sections=[(0x401000,0x12000,116)],_handoff_loader_sections={0x401000})
    assert _generic_handoff_eligible(unpacker,0x401000+offset,Unscannable(),resolved) is expected


def test_progress_is_bounded_diagnostic_evidence_and_rejects_links(tmp_path):
    import json
    from unpacker.unpackers._unipacker_shared import _write_engine_progress
    from unpacker.backend_worker import _progress_metadata
    engine=N(_unpacker_instructions=65536,_unpacker_last_address=0x401234,apicall_counter={'GetProcAddress':3},sections_executed={'stub':5})
    path=tmp_path/'.emulation-progress.json';_write_engine_progress(engine,path)
    result=_progress_metadata(tmp_path)['worker_progress'];assert result['instructions']==65536 and result['api_calls']['GetProcAddress']==3
    path.unlink();path.symlink_to(tmp_path/'foreign')
    assert _progress_metadata(tmp_path)=={}
    path.unlink();path.write_text('[]');assert _progress_metadata(tmp_path)=={}


def test_importless_loader_shim_allows_only_an_actually_empty_directory():
    from unpacker.unpackers._unipacker_shared import _optional_import_parser
    class Parser:
        def __init__(self,rva=0):self.OPTIONAL_HEADER=N(DATA_DIRECTORY=[N(),N(VirtualAddress=rva,Size=0)])
    wrapped=_optional_import_parser(Parser)
    assert wrapped().DIRECTORY_ENTRY_IMPORT==[]
    with pytest.raises(ValueError):wrapped(0x1000)


def test_import_symbol_names_do_not_hide_wrong_iat_pointer_values():
    from unpacker.reconstruction import import_iat_consistency
    data={0x2000:(0x9999).to_bytes(4,'little'),0x2100:(0x3000).to_bytes(4,'little'),0x2004:bytes(4)}
    pe=N(OPTIONAL_HEADER=N(Magic=0x10b),DIRECTORY_ENTRY_IMPORT=[N(struct=N(FirstThunk=0x2000,OriginalFirstThunk=0x2100),imports=[N(name=b'ExitProcess')])],get_data=lambda rva,count:data[rva])
    assert not import_iat_consistency(pe)['passed']
    data[0x2000]=data[0x2100];assert import_iat_consistency(pe)['passed']
    data[0x2004]=b'bad!';assert not import_iat_consistency(pe)['passed']


def test_retained_memory_imports_must_match_observed_symbols_uniquely():
    from unpacker.pe_rebuilder.imports import find_retained_import_table
    pe,sections,data=imports_fixture();struct.pack_into('<II',data,0x140,0x123,0x124);memory=bytes(4096)+bytes(data)
    sections[0].VirtualSize=4096
    observed={'KERNEL32.dll#0':[('ExitProcess',0x123),('ordinal/name/7',0x124)]}
    table=find_retained_import_table(memory,sections,observed)
    assert table and table['rva']==0x1000 and table['symbol_count']==2
    assert find_retained_import_table(memory,sections,{'kernel32.dll':[('Different',1)]}) is None
    assert find_retained_import_table(memory,sections,{}) is None
    damaged=bytearray(memory);struct.pack_into('<I',damaged,0x1140,0x999)
    assert find_retained_import_table(bytes(damaged),sections,observed) is None


def live_header_fixture():
    memory=bytearray(4096);memory[:2]=b'MZ';struct.pack_into('<I',memory,60,128)
    memory[128:132]=b'PE\0\0';struct.pack_into('<HH',memory,132,0x14c,3);struct.pack_into('<H',memory,148,224);struct.pack_into('<H',memory,152,0x10b)
    for index,(start,size,raw) in enumerate([(0x1000,3933,4096),(0x2000,2062,2560),(0,0,0)]):
        struct.pack_into('<III',memory,376+index*40+8,size,start,raw)
    uc=N(mem_read=lambda address,size:memory[address-0x400000:address-0x400000+size])
    return memory,uc


def test_header_only_handoff_parser_accepts_empty_slots_and_retains_zero_raw_reservations():
    from unpacker.unpackers._unipacker_shared import _guest_section_layout,_refresh_handoff_sections,_generic_handoff_eligible
    memory,uc=live_header_fixture()
    assert _guest_section_layout(uc,0x400000)==[(0x1000,4096,4096),(0x2000,2560,2560)]
    unpacker=N(_handoff_original_raw={0x401000:0,0x402000:0},_handoff_initial_sections=[(0x401000,3933,0),(0x402000,2062,0),(0x403000,512,0)],_handoff_loader_sections=set())
    sample=N(BASE_ADDR=0x400000,unpacker=unpacker)
    _refresh_handoff_sections(uc,sample)
    assert _generic_handoff_eligible(unpacker,0x401c56,[(0x401000,0x401fff)],True)
    assert unpacker._handoff_image_sections[-1]==(0x403000,512,0)
    assert sample._unpacker_live_header_updates==1


@pytest.mark.parametrize('mutation',['overlap','header_overlap','count','offset','magic'])
def test_live_header_parser_rejects_unbounded_or_overlapping_layouts(mutation):
    from unpacker.unpackers._unipacker_shared import _guest_section_layout
    memory,uc=live_header_fixture()
    if mutation=='overlap':struct.pack_into('<I',memory,416+12,0x1000)
    if mutation=='header_overlap':struct.pack_into('<I',memory,376+12,0)
    if mutation=='count':struct.pack_into('<H',memory,134,1000)
    if mutation=='offset':struct.pack_into('<I',memory,60,2**32-1)
    if mutation=='magic':memory[:2]=b'XX'
    with pytest.raises(ValueError):_guest_section_layout(uc,0x400000)


def test_retained_import_superset_mode_is_opt_in_and_corroborates_every_iat_binding():
    from unpacker.pe_rebuilder.imports import find_retained_import_table
    pe,sections,data=imports_fixture();struct.pack_into('<II',data,0x140,0x123,0x124);memory=bytes(4096)+bytes(data)
    sections[0].VirtualSize=4096
    observed={'KERNEL32.dll#0':[('ExitProcess',0x123),('ordinal/name/7',0x124),('VirtualProtect',0x125)]}
    assert find_retained_import_table(memory,sections,observed) is None
    table=find_retained_import_table(memory,sections,observed,allow_observed_superset=True)
    assert table and table['symbol_count']==2
    observed['KERNEL32.dll#0'][0]=('ExitProcess',0x999)
    assert find_retained_import_table(memory,sections,observed,allow_observed_superset=True) is None


def rebuilt_import_pe():
    _,sections,imports=imports_fixture();data=bytearray(512+4096)
    data[:2]=b'MZ';struct.pack_into('<I',data,60,128);data[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',data,132,0x14c,1,0,0,0,224,0x102)
    optional=152;struct.pack_into('<H',data,optional,0x10b)
    struct.pack_into('<I',data,optional+16,0x1000);struct.pack_into('<I',data,optional+28,0x400000)
    struct.pack_into('<II',data,optional+32,4096,512);struct.pack_into('<II',data,optional+56,8192,512)
    struct.pack_into('<H',data,optional+68,3);struct.pack_into('<I',data,optional+92,16)
    struct.pack_into('<II',data,optional+104,0x1000,20)
    data[376:384]=b'.idata\0\0';struct.pack_into('<IIII',data,384,4096,0x1000,4096,512)
    struct.pack_into('<I',data,412,0xc0000040)
    imports[20:40]=b'X'*20;data[512:]=imports
    return bytes(data)


def test_rebuilt_import_terminator_repairs_only_valid_counted_table():
    import pefile
    from unpacker.pe_rebuilder.imports import normalize_rebuilt_terminator
    from unpacker.reconstruction import import_descriptor_consistency
    raw=rebuilt_import_pe();before=pefile.PE(data=raw)
    assert not import_descriptor_consistency(before)['passed'];before.close()
    repaired,facts=normalize_rebuilt_terminator(raw);pe=pefile.PE(data=repaired)
    try:
        assert facts=={'descriptors':1,'symbols':2,'terminator_rva':0x1014}
        assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size==40
        assert pe.get_data(0x1014,20)==bytes(20) and import_descriptor_consistency(pe)['passed']
        assert repaired[512+0x100:]==raw[512+0x100:]
    finally:pe.close()


def test_rebuilt_terminator_rejects_misdeclared_count_and_invalid_symbols():
    from unpacker.pe_rebuilder.imports import normalize_rebuilt_terminator
    raw=bytearray(rebuilt_import_pe());struct.pack_into('<I',raw,152+108,40)
    with pytest.raises(ValueError):normalize_rebuilt_terminator(bytes(raw))
    raw=bytearray(rebuilt_import_pe());struct.pack_into('<I',raw,512+0x100,0xdeadbeef)
    with pytest.raises(ValueError):normalize_rebuilt_terminator(bytes(raw))


def test_compact_pe_offset_is_supported_without_assuming_dos_stub_length():
    from unpacker.unpackers._unipacker_shared import _guest_section_layout
    memory=bytearray(4096);memory[:2]=b'MZ';memory[16:20]=b'PE\0\0'
    struct.pack_into('<HH',memory,20,0x14c,1);struct.pack_into('<H',memory,36,224)
    struct.pack_into('<H',memory,40,0x10b);struct.pack_into('<I',memory,60,16)
    struct.pack_into('<III',memory,264+8,4096,4096,4096)
    uc=N(mem_read=lambda address,size:memory[address-0x400000:address-0x400000+size])
    assert _guest_section_layout(uc,0x400000)==[(4096,4096,4096)]


def test_valid_import_directory_is_preserved_even_when_size_includes_terminator():
    from unpacker.pe_rebuilder.imports import normalize_rebuilt_terminator
    raw=bytearray(rebuilt_import_pe());raw[512+20:512+40]=bytes(20)
    struct.pack_into('<I',raw,152+108,40)
    normalized,facts=normalize_rebuilt_terminator(bytes(raw))
    assert normalized==raw and facts['already_valid']
