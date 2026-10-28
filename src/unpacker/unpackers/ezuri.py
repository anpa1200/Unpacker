"""Static recovery of Ezuri's appended key/IV/AES-CFB ELF payload.

Layout follows guitmz/ezuri's writer. The paired original is never read here.
This is decryption of an acquired artifact, not execution of its loader.
"""
from unpacker.types import UnpackResult
from unpacker.unpackers.base import BaseUnpacker
from unpacker.elf_notes import elf_file_extent,bounded_elf


def ezuri_layout(data):
    if b'main.runFromMemory' not in data:raise ValueError('Ezuri loader marker is absent')
    end=elf_file_extent(data)
    if len(data)-end<16+16+64:raise ValueError('No bounded Ezuri trailer')
    return end


class EzuriUnpacker(BaseUnpacker):
    @property
    def packer_id(self):return 'ezuri'

    def unpack(self,sample_path,options):
        from unpacker.backend_worker import supervise
        return supervise('ezuri_static',sample_path,options.output_dir/'payload.bin',options,'ezuri_static')


def _extract_ezuri(sample_path,out_path,options):
    if sample_path.stat().st_size>options.max_input_size_mb*1024*1024:return UnpackResult(False,error='Input exceeds budget',status='input_error')
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms
        try:from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:from cryptography.hazmat.primitives.ciphers.modes import CFB
    except ImportError:
        return UnpackResult(False,error='Ezuri static recovery requires the optional crypto extra',status='dependency_error')
    try:
        data=sample_path.read_bytes();end=ezuri_layout(data);candidates=[]
        for key_size in [16,24,32]:
            start=end+key_size+16;length=len(data)-start
            if not 64<=length<=options.max_output_size_mb*1024*1024:continue
            key=data[end:end+key_size];iv=data[end+key_size:start]
            decryptor=Cipher(algorithms.AES(key),CFB(iv)).decryptor()
            head=decryptor.update(data[start:start+64])
            if not head.startswith(b'\x7fELF'):continue
            payload=head+decryptor.update(data[start+64:])+decryptor.finalize()
            elf=bounded_elf(payload);loads=[]
            for segment in elf.iter_segments():
                if segment['p_offset']+segment['p_filesz']>len(payload):raise ValueError('Decrypted segment exceeds payload')
                if segment['p_type']=='PT_LOAD':
                    if segment['p_filesz']>segment['p_memsz']:raise ValueError('Decrypted file segment exceeds memory size')
                    loads.append(segment)
            entry=elf.header['e_entry']
            if not loads or not any(s['p_flags']&1 and s['p_vaddr']<=entry<s['p_vaddr']+s['p_filesz'] for s in loads):raise ValueError('Decrypted entry is not file-backed executable data')
            if elf_file_extent(payload)!=len(payload):raise ValueError('Unsupported trailing bytes in decrypted ELF')
            candidates.append((payload,key_size,start))
        if len(candidates)!=1:raise ValueError('No unique structurally valid Ezuri trailer decryption')
        payload,key_size,start=candidates[0]
        with out_path.open('xb') as output:output.write(payload)
        out_path.chmod(0o600)
        return UnpackResult(True,output_path=out_path,status='completed',artifact_kind='decompressed_file',metadata={
            'method':'ezuri_static','scope':'contained_file_only','algorithm':'AES-CFB128','key_bytes':key_size,
            'trailer_offset':end,'payload_offset':start,'payload_bytes':len(payload),'authentication':'format_has_no_authentication'})
    except (ValueError,TypeError,KeyError,IndexError) as exc:
        return UnpackResult(False,error=str(exc),status='unsupported',metadata={'method':'ezuri_static'})
