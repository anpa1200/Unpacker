"""Conservative extraction of retained PE32 cores in Enigma Virtual Box layouts.

This does not reconstruct the embedded virtual filesystem or arbitrary Enigma
protector versions. No paired original is consulted during extraction.
"""
import struct
from pathlib import Path
from unpacker.types import UnpackResult
from unpacker.unpackers.base import BaseUnpacker


class EnigmaUnpacker(BaseUnpacker):
    @property
    def packer_id(self):return 'enigma'

    def unpack(self,sample_path,options):
        from unpacker.backend_worker import supervise
        return supervise('enigma_static',sample_path,options.output_dir/'core.bin',options,'enigma_retained_core')


def _extract_core(sample_path,out_path,options):
    import pefile
    from unpacker.pe_rebuilder.imports import retained_import_table,file_backed_data
    if sample_path.stat().st_size>options.max_input_size_mb*1024*1024:return UnpackResult(False,error='Input exceeds budget',status='input_error')
    pe=pefile.PE(str(sample_path),fast_load=False)
    try:
        names=[s.Name.rstrip(b'\0').lower() for s in pe.sections]
        if names[-2:]!=[b'.enigma1',b'.enigma2'] or len(names)<3:raise ValueError('Not a supported retained-core Enigma Virtual Box layout')
        core=pe.sections[:-2];wrapper=pe.sections[-2:]
        first_wrapper=min(s.VirtualAddress for s in wrapper)
        core_end=max(s.PointerToRawData+s.SizeOfRawData for s in core if s.SizeOfRawData)
        if any(s.SizeOfRawData and s.PointerToRawData<core_end for s in wrapper):raise ValueError('Container overlaps retained file data')
        if any(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)>first_wrapper for s in core):raise ValueError('Container overlaps retained virtual data')
        entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if not any(s.Characteristics&0x20000000 and s.VirtualAddress<=entry<s.VirtualAddress+min(s.Misc_VirtualSize or s.SizeOfRawData,s.SizeOfRawData) for s in core):raise ValueError('Entry is outside retained executable data')
        candidates=[]
        for section in core:
            if section.Name.rstrip(b'\0').lower()==b'.idata':
                try:candidates.append(retained_import_table(pe,section.VirtualAddress,core))
                except ValueError:pass
        if len(candidates)!=1:raise ValueError('No unique validated retained import table')
        table=candidates[0]
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress==table['rva']:raise ValueError('Input already uses retained imports')
        tls=pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        if tls.Size!=24:raise ValueError('Unsupported wrapper TLS layout')
        tls_data=file_backed_data(pe,tls.VirtualAddress,24,wrapper)
        callback_va=struct.unpack('<IIIIII',tls_data)[3]
        callbacks=[]
        for index in range(33):
            address=struct.unpack('<I',file_backed_data(pe,callback_va-pe.OPTIONAL_HEADER.ImageBase+index*4,4,wrapper))[0]
            if not address:break
            if index==32 or not any(s.VirtualAddress<=address-pe.OPTIONAL_HEADER.ImageBase<s.VirtualAddress+min(s.Misc_VirtualSize or s.SizeOfRawData,s.SizeOfRawData) for s in wrapper):raise ValueError('TLS callback escapes removed wrapper')
            callbacks.append(address)
        if not callbacks:raise ValueError('No validated wrapper TLS callbacks')
        for index,directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if index in {1,9} or not directory.VirtualAddress:continue
            if index==4:raise ValueError('Signed container needs separate certificate handling')
            file_backed_data(pe,directory.VirtualAddress,max(1,directory.Size),core)
        # Restore loader-ready IAT values only from the validated input lookup table.
        for descriptor in table['descriptors']:
            for index,value in enumerate(descriptor['lookup_values']+[0]):
                pe.set_dword_at_rva(descriptor['iat_rva']+index*4,value)
        pe.FILE_HEADER.NumberOfSections=len(core)
        alignment=pe.OPTIONAL_HEADER.SectionAlignment
        if alignment<=0 or alignment&(alignment-1):raise ValueError('Invalid section alignment')
        image_end=max(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) for s in core)
        pe.OPTIONAL_HEADER.SizeOfImage=(image_end+alignment-1)//alignment*alignment
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress=table['rva']
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size=table['descriptor_bytes']
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress=0;pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size=0
        data=bytearray(pe.write()[:core_end])
        for section in wrapper:
            offset=section.get_file_offset();data[offset:offset+40]=bytes(40)
        if not 0<len(data)<=options.max_output_size_mb*1024*1024:raise ValueError('Core exceeds output budget')
        checked=pefile.PE(data=bytes(data),fast_load=False)
        try:
            if sum(len(e.imports) for e in getattr(checked,'DIRECTORY_ENTRY_IMPORT',[]))!=table['symbol_count']:raise ValueError('Restored import count differs')
            checked.OPTIONAL_HEADER.CheckSum=checked.generate_checksum();data=checked.write()
        finally:checked.close()
        with out_path.open('xb') as output:output.write(data)
        out_path.chmod(0o600)
        warning='Embedded virtual filesystem and wrapper TLS behavior are not reconstructed'
        return UnpackResult(False,output_path=out_path,status='partial',artifact_kind='reconstructed_pe',error=warning,warnings=[warning],metadata={
            'method':'enigma_retained_core_static','recovered_import_symbols':table['symbol_count'],
            'retained_sections':len(core),'removed_sections':names[-2:][0].decode()+','+names[-1].decode(),
            'removed_tls_callbacks':callbacks,'discarded_container_bytes':sample_path.stat().st_size-len(data),
            'complete_recovery':'not_established','scope':'retained_core_only'})
    except (ValueError,IndexError,struct.error) as exc:
        return UnpackResult(False,error=str(exc),status='unsupported',metadata={'method':'enigma_retained_core_static'})
    finally:pe.close()
