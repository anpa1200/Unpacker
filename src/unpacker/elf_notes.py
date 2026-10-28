"""Recognize a bounded, uncompressed ELF payload carried by an appended PT_NOTE.

This is the layout used by ward's injector, not a general ELF decryption engine.
No path embedded in the ELF is opened; bytes are never executed.
"""
import io,struct
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def bounded_elf(data):
    if len(data)<52 or data[:4]!=b'\x7fELF' or data[4] not in {1,2} or data[5] not in {1,2}:
        raise ValueError('Invalid ELF identification')
    is64=data[4]==2;endian='<' if data[5]==1 else '>'
    header_size=64 if is64 else 52
    if len(data)<header_size:raise ValueError('Truncated ELF header')
    fields=struct.unpack_from(endian+('HHIQQQIHHHHHH' if is64 else 'HHIIIIIHHHHHH'),data,16)
    phoff,shoff,ehsize,phsize,phnum,shsize,shnum,shstr=fields[4],fields[5],*fields[7:]
    if fields[0] not in {2,3} or ehsize!=header_size or not 0<phnum<=128 or shnum>4096:
        raise ValueError('Unsupported ELF header/counts')
    if phsize!=(56 if is64 else 32) or phoff+phnum*phsize>len(data):raise ValueError('Invalid program-header bounds')
    if shnum:
        if shsize!=(64 if is64 else 40) or shstr>=shnum or shoff+shnum*shsize>len(data):raise ValueError('Invalid section-header bounds')
    elif shoff or shstr:raise ValueError('Extended ELF section counts are not supported')
    try:elf=ELFFile(io.BytesIO(data))
    except ELFError as exc:raise ValueError('Invalid ELF structure') from exc
    h=elf.header
    if h['e_type'] not in {'ET_EXEC','ET_DYN'} or not 0<h['e_phnum']<=128 or h['e_shnum']>4096:
        raise ValueError('Unsupported ELF type or table count')
    expected_ph=56 if elf.elfclass==64 else 32
    expected_sh=64 if elf.elfclass==64 else 40
    if h['e_phentsize']!=expected_ph or h['e_phoff']+h['e_phnum']*expected_ph>len(data):
        raise ValueError('Invalid program-header bounds')
    if h['e_shnum'] and (h['e_shentsize']!=expected_sh or h['e_shoff']+h['e_shnum']*expected_sh>len(data)):
        raise ValueError('Invalid section-header bounds')
    return elf


def note_payload(data,limit):
    if not data.startswith(b'\x7fELF'):raise ValueError('Input is not ELF')
    elf=bounded_elf(data);segments=list(elf.iter_segments())
    candidates=[];carrier_end=max(elf.header['e_ehsize'],elf.header['e_phoff']+elf.header['e_phnum']*elf.header['e_phentsize'],elf.header['e_shoff']+elf.header['e_shnum']*elf.header['e_shentsize'])
    for seg in segments:
        off,size=seg['p_offset'],seg['p_filesz']
        if off+size>len(data):raise ValueError('Carrier segment exceeds input')
        if seg['p_type']!='PT_NOTE':carrier_end=max(carrier_end,off+size)
    for section in elf.iter_sections():
        if section['sh_type']!='SHT_NOBITS':
            end=section['sh_offset']+section['sh_size']
            if end>len(data):raise ValueError('Carrier section exceeds input')
            carrier_end=max(carrier_end,end)
    for seg in segments:
        off,size=seg['p_offset'],seg['p_filesz']
        if seg['p_type']!='PT_NOTE' or not 64<=size<=limit or size<=seg['p_memsz'] or off<carrier_end or off+size!=len(data):continue
        candidate=data[off:off+size]
        if not candidate.startswith(b'\x7fELF'):continue
        inner=bounded_elf(candidate);loads=[]
        for part in inner.iter_segments():
            if part['p_offset']+part['p_filesz']>size:raise ValueError('Payload segment exceeds file')
            if part['p_type']=='PT_LOAD':
                if part['p_filesz']>part['p_memsz']:raise ValueError('Payload file segment exceeds memory size')
                loads.append(part)
        entry=inner.header['e_entry']
        if not loads or not entry or not any(p['p_flags']&1 and p['p_vaddr']<=entry<p['p_vaddr']+p['p_filesz'] for p in loads):raise ValueError('Payload entry is not file-backed executable data')
        for section in inner.iter_sections():
            if section['sh_type']!='SHT_NOBITS' and section['sh_offset']+section['sh_size']>size:raise ValueError('Payload section exceeds file')
        candidates.append((off,size))
    if len(candidates)!=1:raise ValueError('No unique supported appended ELF note payload')
    return candidates[0]


def elf_file_extent(data):
    """Last file-backed ELF byte, excluding any appended trailer."""
    elf=bounded_elf(data);h=elf.header
    end=max(h['e_ehsize'],h['e_phoff']+h['e_phnum']*h['e_phentsize'],h['e_shoff']+h['e_shnum']*h['e_shentsize'])
    for segment in elf.iter_segments():
        end=max(end,segment['p_offset']+segment['p_filesz'])
    for section in elf.iter_sections():
        if section['sh_type']!='SHT_NOBITS':end=max(end,section['sh_offset']+section['sh_size'])
    if end>len(data):raise ValueError('ELF file-backed extent exceeds input')
    return end
