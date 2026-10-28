"""Independent pefile checks of benign generated module metadata; no execution."""
import struct
import pefile
import pytest
from unpacker.desktop_catalog import EXPORT_NAMES
from unpacker.guest_export_image import build_export_image


@pytest.mark.parametrize('module',sorted(EXPORT_NAMES))
def test_catalog_export_views_are_parseable_sorted_and_point_to_code(module):
    view=build_export_image(module,EXPORT_NAMES[module],0x61000000,0x104000)
    pe=pefile.PE(data=view['image'])
    try:
        names=[e.name.decode('ascii') for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        assert names==sorted(EXPORT_NAMES[module])
        assert pe.FILE_HEADER.Machine==0x14c and pe.FILE_HEADER.Characteristics&0x2000
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint==0 and pe.OPTIONAL_HEADER.SizeOfImage==len(view['image'])
        assert pe.DIRECTORY_ENTRY_EXPORT.name==module.encode()
        directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            assert entry.forwarder is None and not directory.VirtualAddress<=entry.address<directory.VirtualAddress+directory.Size
            assert view['base']+entry.address==view['exports'][entry.name.decode()]
            assert pe.get_data(entry.address,8)==b'\x8b\x04\x25'+struct.pack('<I',0x104000)+b'\xc3'
        assert pe.sections[0].Characteristics==0x40000040 and pe.sections[1].Characteristics==0x60000020
    finally:pe.close()


def test_name_order_and_ordinal_indices_agree_with_manual_binary_lookup():
    view=build_export_image('user32.dll',['Zulu','Alpha','Middle'],0x61000000,0x104000)
    data=view['image'];rva=struct.unpack_from('<I',data,152+96)[0]
    count,eat,pointers,ordinals=struct.unpack_from('<IIII',data,rva+24)
    assert count==3
    for index,symbol in enumerate(['Alpha','Middle','Zulu']):
        name=struct.unpack_from('<I',data,pointers+4*index)[0]
        assert data[name:].split(b'\0',1)[0].decode()==symbol
        ordinal=struct.unpack_from('<H',data,ordinals+2*index)[0]
        address=view['base']+struct.unpack_from('<I',data,eat+ordinal*4)[0]
        assert address==view['exports'][symbol]


@pytest.mark.parametrize('names',[[],['A','A'],['bad.name'],['A\0B'],['x']*2049])
def test_invalid_export_name_sets_are_rejected(names):
    with pytest.raises(ValueError):build_export_image('user32.dll',names,0x61000000,0x104000)


@pytest.mark.parametrize('base',[0,0x61000001,0xffff0000,True])
def test_invalid_module_bases_cannot_produce_wrapped_addresses(base):
    with pytest.raises(ValueError):build_export_image('user32.dll',['MessageBoxA'],base,0x104000)


def test_data_exports_are_rw_nx_storage_not_callable_return_stubs():
    view=build_export_image('msvcrt.dll',['__getmainargs'],0x61000000,0x104000,
                            {'_acmdln':bytes(4),'_adjust_fdiv':bytes(4)})
    pe=pefile.PE(data=view['image'])
    try:
        assert pe.sections[1].Name.rstrip(b'\0')==b'.data' and pe.sections[1].Characteristics==0xc0000040
        for symbol,address in view['data_exports'].items():
            assert pe.get_data(address-view['base'],4)==bytes(4)
            entry=next(e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name.decode()==symbol)
            assert entry.forwarder is None and entry.address==address-view['base']
    finally:pe.close()


def test_relocatable_dispatch_thunks_use_unique_validated_identifiers():
    view=build_export_image('user32.dll',['Z','A'],0x61000000,0x104000,dispatch_ids={'A':12,'Z':14})
    for symbol,identifier in [('A',12),('Z',14)]:
        offset=view['exports'][symbol]-view['base']
        assert view['image'][offset:offset+8]==b'\x0f\x0b'+struct.pack('<H',identifier)+b'\xc3\x90\x90\x90'


@pytest.mark.parametrize('identifiers',[{}, {'A':0}, {'A':True}, {'A':2**16}, {'A':1,'Z':2}])
def test_incomplete_or_invalid_dispatch_identifiers_are_rejected(identifiers):
    with pytest.raises(ValueError):build_export_image('user32.dll',['A'],0x61000000,0x104000,dispatch_ids=identifiers)
