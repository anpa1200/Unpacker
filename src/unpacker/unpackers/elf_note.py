"""Read-only extraction of uncompressed ward-compatible ELF note containers."""
from unpacker.types import UnpackResult
from unpacker.unpackers.base import BaseUnpacker


class ELFNoteUnpacker(BaseUnpacker):
    @property
    def packer_id(self):return 'elf_note'

    def can_handle(self,packer_id,sample_path):return packer_id.lower() in {'ward','elf_note'}

    def unpack(self,sample_path,options):
        from unpacker.backend_worker import supervise
        return supervise('elf_note_static',sample_path,options.output_dir/'payload.bin',options,'elf_note_static')


def _extract_note(sample_path,out_path,options):
    from unpacker.elf_notes import note_payload
    if sample_path.stat().st_size>options.max_input_size_mb*1024*1024:return UnpackResult(False,error='Input exceeds budget',status='input_error')
    try:
        data=sample_path.read_bytes();offset,size=note_payload(data,options.max_output_size_mb*1024*1024)
        with out_path.open('xb') as output:output.write(data[offset:offset+size])
        out_path.chmod(0o600)
        return UnpackResult(True,output_path=out_path,status='completed',artifact_kind='decompressed_file',metadata={
            'method':'elf_note_static','layout':'uncompressed_appended_pt_note','payload_offset':offset,'payload_bytes':size,'scope':'contained_file_only'})
    except (ValueError,TypeError,KeyError,IndexError) as exc:
        return UnpackResult(False,error=str(exc),status='unsupported',metadata={'method':'elf_note_static'})
