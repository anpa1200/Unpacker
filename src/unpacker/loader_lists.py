"""PE32 loader-list metadata for modules already mapped by the emulator.

Only guest memory is updated. This does not load a DLL, resolve a host symbol,
initialize module code, or implement the rest of the Windows process ABI.
"""
import struct


def _image_info(uc, base):
    dos = bytes(uc.mem_read(base, 64))
    if len(dos) != 64 or dos[:2] != b'MZ':
        raise ValueError('Mapped module has no DOS header')
    offset = struct.unpack_from('<I', dos, 60)[0]
    if not 4 <= offset <= 4096:
        raise ValueError('Mapped module PE offset exceeds loader budget')
    header = bytes(uc.mem_read(base+offset, 84))
    if len(header) != 84 or header[:4] != b'PE\0\0' or struct.unpack_from('<HH', header, 4)[0] != 0x14c:
        raise ValueError('Mapped loader-list module is not PE32 x86')
    if struct.unpack_from('<H', header, 24)[0] != 0x10b:
        raise ValueError('Mapped loader-list module has unsupported optional header')
    entry, size = struct.unpack_from('<I', header, 40)[0], struct.unpack_from('<I', header, 80)[0]
    if not 0 < size <= 64*1024*1024 or entry >= size or base+size > 0x100000000:
        raise ValueError('Mapped loader-list module extent is invalid')
    # Existing backend DLL snapshots omit trailing alignment padding. Preserve
    # the declared SizeOfImage in metadata without mapping invented bytes.
    if entry and not any(lo <= base+entry <= hi and permissions & 4 for lo, hi, permissions in uc.mem_regions()):
        raise ValueError('Loader-list entry point is not mapped executable memory')
    return base+entry if entry else 0, size


def install_loader_lists(engine):
    uc = engine.uc
    ldr = engine.PEB_BASE+0x1000
    entries = ldr+0x1000
    strings = ldr+0x2000
    if not any(lo <= ldr and strings+4095 <= hi for lo, hi, _ in uc.mem_regions()):
        raise ValueError('Reserved loader metadata memory is not mapped')
    modules = [
        ('sample.bin', engine.sample.BASE_ADDR, 'C:\\sample.bin'),
        ('ntdll.dll', 0x77400000, 'C:\\Windows\\System32\\ntdll.dll'),
        ('kernel32.dll', 0x755d0000, 'C:\\Windows\\System32\\kernel32.dll'),
        ('KernelBase.dll', 0x73d00000, 'C:\\Windows\\System32\\KernelBase.dll'),
    ]
    extra=list(getattr(engine,'_unpacker_extra_modules',()))
    if len(extra)>12:raise ValueError('Guest module-list budget exceeded')
    for row in extra:
        if not isinstance(row,(tuple,list)) or len(row)!=3:raise ValueError('Invalid extra module identity')
        name,base,full=row
        if (not isinstance(name,str) or not 1<=len(name)<=127 or not name.isascii() or
            not name.lower().endswith('.dll') or type(base) is not int or not isinstance(full,str) or len(full)>512):
            raise ValueError('Invalid extra module identity')
        modules.append((name,base,full))
    if len({name.lower() for name,_,_ in modules})!=len(modules) or len({base for _,base,_ in modules})!=len(modules):
        raise ValueError('Duplicate loaded module identity')
    payloads = [];images=[]
    cursor = strings
    for index, (name, base, full) in enumerate(modules):
        entrypoint, size = _image_info(uc, base)
        images.append({'name':name,'base':base,'full_name':full,'entrypoint':entrypoint,'image_size':size})
        entry = bytearray(0x80)
        struct.pack_into('<III', entry, 0x18, base, entrypoint, size)
        for offset, value in [(0x24, full), (0x2c, name)]:
            encoded = value.encode('utf-16le')
            payload = encoded+b'\0\0'
            if cursor+len(payload) > strings+4096:
                raise ValueError('Loader name budget exceeded')
            struct.pack_into('<HHI', entry, offset, len(encoded), len(payload), cursor)
            payloads.append((cursor, payload))
            cursor += len(payload)
        payloads.append((entries+index*0x80, entry))
    # Complete rings use the address of each embedded LIST_ENTRY, including
    # head-relative links and backlink fields. Initialization excludes the EXE.
    lists = [(0x0c, 0, list(range(len(modules)))), (0x14, 8, list(range(len(modules)))),
             (0x1c, 16, [1, 3, 2,*range(4,len(modules))])]
    header = bytearray(0x30)
    struct.pack_into('<II', header, 0, len(header), 1)
    for head_offset, link_offset, indices in lists:
        head = ldr+head_offset
        nodes = [entries+index*0x80+link_offset for index in indices]
        struct.pack_into('<II', header, head_offset, nodes[0], nodes[-1])
        for index, node in enumerate(nodes):
            previous = nodes[index-1] if index else head
            following = nodes[index+1] if index+1 < len(nodes) else head
            payloads.append((node, struct.pack('<II', following, previous)))
    # All header/bounds checks complete before changing any guest bytes.
    for address, payload in payloads:
        uc.mem_write(address, bytes(payload))
    uc.mem_write(ldr, bytes(header))
    uc.mem_write(engine.PEB_BASE+0x0c, struct.pack('<I', ldr))
    return {'abi': 'windows7_pe32_loader_lists', 'modules': [name for name, _, _ in modules],
            'module_images':images,
            'scope': 'already_mapped_modules_only', 'process_parameters': 'not_implemented'}
