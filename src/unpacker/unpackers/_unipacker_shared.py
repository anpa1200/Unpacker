"""
Shared Unipacker emulation logic for ASPack, Themida, and other PE packers.
Patches Unipacker for robust dumping (safe memory read, survive fix_imports failure).
"""
from __future__ import annotations

import contextlib
import io
import threading
import json
import tempfile
import os
from pathlib import Path

from unpacker.types import UnpackOptions, UnpackResult
from unpacker.write_ranges import WriteRangeTracker

_PAGE = 0x1000
_PATCH_INSTALLED = False
_MAX_DUMP_BYTES = 32 * 1024 * 1024
_DUMP_WARNINGS = []
_MISSING_READ_BYTES = 0
_DUMP_STATE = {}


class _ImportsNotReady(ValueError):
    """Detached reconstruction proved there is no usable import directory."""

UNIPACKER_INSTALL_HINT = (
    "Install the reviewed Linux emulation runtime from the release bundle using "
    "its hashed lock and offline wheelhouse. The maintained Unicorn binding "
    "does not require deprecated distutils/pkg_resources compatibility."
)


def _safe_uc_mem_read(uc, base_addr: int, size: int) -> bytes:
    global _MISSING_READ_BYTES
    if not 0 < size <= _MAX_DUMP_BYTES:
        raise ValueError("Dump memory size exceeds configured budget")
    try:
        return uc.mem_read(base_addr, size)
    except Exception:
        pass
    data = bytearray(size)
    for off in range(0, size, _PAGE):
        chunk_len = min(_PAGE, size - off)
        try:
            chunk = uc.mem_read(base_addr + off, chunk_len)
            data[off : off + chunk_len] = chunk
        except Exception:
            _MISSING_READ_BYTES += chunk_len
    return bytes(data)


def _contiguous_image_span(uc,base_addr):
    frontier=base_addr
    for start,end,permissions in sorted(uc.mem_regions()):
        if end<frontier:continue
        if start>frontier:break
        frontier=end+1
        if frontier-base_addr>_MAX_DUMP_BYTES:raise ValueError('Contiguous image exceeds dump budget')
    if frontier<=base_addr:raise ValueError('Image base is not mapped')
    return frontier-base_addr


def _mark_handoff_section_executable(hdr):
    """Record a conservative permission repair, never a completeness claim.

    Unipacker maps the whole image RWX. A handoff can therefore target a section
    whose packed header is non-executable; that mismatch must remain observable.
    """
    entry=hdr.opt_header.AddressOfEntryPoint
    for section in hdr.section_list:
        if section.VirtualAddress<=entry<section.VirtualAddress+min(section.VirtualSize,section.SizeOfRawData):
            if not section.Characteristics&0x20000000:
                section.Characteristics|=0x20000000
                return True
            return False
    return False


def _handoff_key(sample,address):
    page=address//_PAGE
    writes=getattr(sample,'_unpacker_external_writes',{})
    return (page,getattr(sample,'_unpacker_import_epoch',0),writes.get(page,0))


def _strict_find_iat(self,uc,base_addr,total_size,iat_array,dll_name,offset=4):
    from unpacker.pe_rebuilder.iat_search import find_unique_iat
    if offset!=4 or not 0<total_size<=_MAX_DUMP_BYTES:
        raise ValueError('IAT search supports bounded PE32 arrays only')
    memory=bytes(uc.mem_read(base_addr,total_size))
    if len(memory)!=total_size:raise ValueError('Truncated IAT search image')
    facts=find_unique_iat(memory,iat_array)
    if facts['reason']=='ambiguous_complete_sequences':
        from unicorn.x86_const import UC_X86_REG_EIP
        from unpacker.pe_rebuilder.iat_provenance import reachable_iat_slots,select_referenced_iat
        try:
            pc=uc.reg_read(UC_X86_REG_EIP)
            regions=[(start,size) for start,size,raw in _guest_section_layout(uc,base_addr) if start<=pc-base_addr<start+size]
            if len(regions)!=1:raise ValueError('No unique handoff code region')
            start,size=regions[0]
            import struct
            bindings=getattr(self,'_unpacker_dialog_bindings',{})
            source=getattr(uc,'cpu',uc)
            def callback_resolver(slot):
                if not base_addr<=slot<=base_addr+total_size-4:return None
                value=struct.unpack('<I',source.mem_read(slot,4))[0]
                return (5,4) if value in bindings else None
            provenance=reachable_iat_slots(memory[start:start+size],base_addr+start,pc,callback_resolver=callback_resolver)
            selected=select_referenced_iat(facts['candidate_rvas'],len(iat_array),base_addr,provenance)
            facts['code_provenance']={key:value for key,value in provenance.items() if key!='slots'}
            facts['code_provenance']['absolute_slots_found']=len(provenance['slots'])
            if selected is not None:
                facts.update(rva=selected,reason='unique_complete_sequence_referenced_from_handoff_region')
        except (ValueError,IndexError,ImportError) as exc:
            facts['provenance_error']=str(exc)[:160]
    _DUMP_STATE['iat_search_count']=_DUMP_STATE.get('iat_search_count',0)+1
    records=_DUMP_STATE.setdefault('iat_searches',[])
    if len(records)<32:records.append({'module':str(dll_name)[:128],'symbols':len(iat_array),**facts})
    return facts['rva']


def _guest_section_layout(uc,base):
    """Bounded PE32 headers only; never traverse a transient import directory."""
    import struct
    dos=bytes(uc.mem_read(base,64))
    if len(dos)!=64 or dos[:2]!=b'MZ':raise ValueError('Invalid live DOS header')
    offset=struct.unpack_from('<I',dos,60)[0]
    if not 4<=offset<=65536:raise ValueError('Invalid live PE offset')
    header=bytes(uc.mem_read(base+offset,24))
    if len(header)!=24 or header[:4]!=b'PE\0\0':raise ValueError('Invalid live PE signature')
    machine,count=struct.unpack_from('<HH',header,4);optional=struct.unpack_from('<H',header,20)[0]
    if machine!=0x14c or not 1<=count<=96 or optional!=224:raise ValueError('Unsupported live PE32 layout')
    table=offset+24+optional
    if table+count*40>65536:raise ValueError('Live section table exceeds header budget')
    if bytes(uc.mem_read(base+offset+24,2))!=b'\x0b\x01':raise ValueError('Unsupported live optional header')
    sections=[]
    for index in range(count):
        raw=bytes(uc.mem_read(base+table+index*40,40))
        if len(raw)!=40:raise ValueError('Truncated live section header')
        size,start,file_size=struct.unpack_from('<III',raw,8)
        sections.append((start,size,file_size))
    previous_end=0
    valid=[]
    for start,size,file_size in sorted(sections):
        if size==0 and file_size==0:continue
        if start<4096 or start<previous_end or start+max(size,file_size)>_MAX_DUMP_BYTES:raise ValueError('Invalid restored section extents')
        previous_end=start+max(size,file_size);valid.append((start,max(size,file_size),file_size))
    if not valid:raise ValueError('No nonempty live sections')
    return valid


def install_unipacker_patch() -> None:
    global _PATCH_INSTALLED
    if _PATCH_INSTALLED:
        return
    try:
        import unipacker.headers as headers
        from unipacker.imagedump import ImageDump
        from unicorn import UcError
    except ImportError:
        return

    _orig_pe_write = headers.pe_write

    class _SafePeWrite(_orig_pe_write):
        def __init__(self, uc, base_addr, total_size, filename, temporary=False):
            data = _safe_uc_mem_read(uc, base_addr, total_size)
            with open(filename, "wb+") as f:
                f.write(data)
            self.temporary = temporary
            self.filename = filename

    headers.pe_write = _SafePeWrite

    _orig_dump_image = ImageDump.dump_image

    def _dump_image_once(self, uc, base_addr, virtualmemorysize, apicall_handler, sample, path="unpacked.exe"):
        if getattr(sample,'_unpacker_dump_started',False):
            _DUMP_STATE['suppressed_duplicate_dumps']=_DUMP_STATE.get('suppressed_duplicate_dumps',0)+1
            return
        sample._unpacker_dump_started=True
        ntp = apicall_handler.ntp
        dllname_to_functionlist = {name:functions for name,functions in sample.dllname_to_functionlist.items() if functions}
        from unpacker.pe_rebuilder.iat_provenance import dialog_bindings
        self._unpacker_dialog_bindings=dialog_bindings(dllname_to_functionlist)
        total_size=_contiguous_image_span(uc,base_addr)
        _DUMP_STATE.update(requested_image_size=virtualmemorysize,dump_image_size=total_size,image_span_source='live_contiguous_mapping')
        # Freed/stale allocation high-water marks must never expand a file across
        # unmapped holes or move the import-rebuild workspace into unmapped memory.
        live_regions=list(uc.mem_regions())
        outside=[(start,end) for start,end in sample.allocated_chunks
                 if not (base_addr<=start<end<=base_addr+total_size)
                 and any(lo<end and start<=hi for lo,hi,permissions in live_regions)]
        if outside:
            _DUMP_WARNINGS.append('Noncontiguous live allocations are outside the reconstructed image')
        virtualmemorysize=total_size

        try:
            from unipacker.headers import PE, pe_write
            from unipacker.utils import alignments
            from unicorn.x86_const import UC_X86_REG_EIP
        except ImportError:
            return _orig_dump_image(self, uc, base_addr, virtualmemorysize, apicall_handler, sample, path)

        try:
            hdr = PE(uc, base_addr)
        except Exception:
            return

        old_number_of_sections = hdr.pe_header.NumberOfSections
        nonempty=[section for section in hdr.section_list if section.VirtualSize or section.SizeOfRawData]
        if len(nonempty)!=len(hdr.section_list):
            _DUMP_STATE['removed_empty_sections']=len(hdr.section_list)-len(nonempty)
            hdr.section_list=nonempty;hdr.pe_header.NumberOfSections=len(nonempty);old_number_of_sections=len(nonempty)
        hdr.opt_header.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP) - base_addr

        try:
            from unpacker.pe_rebuilder.imports import find_retained_import_table
            retained=find_retained_import_table(bytes(uc.mem_read(base_addr,total_size)),hdr.section_list,dllname_to_functionlist,
                allow_observed_superset=getattr(sample,'_unpacker_input_headers_restored',False))
            if retained is None:
                from unpacker.pe_rebuilder.erased_names import find_erased_import_names
                retained=find_erased_import_names(bytes(uc.mem_read(base_addr,total_size)),hdr.section_list,dllname_to_functionlist)
                if retained is not None:
                    for start,payload in retained['name_patches']:uc.mem_write(base_addr+start,payload)
                    # The restored IAT is unbound; stale binding metadata must
                    # not tell a loader to reuse addresses from the packed file.
                    for index in range(len(retained['descriptors'])):
                        uc.mem_write(base_addr+retained['rva']+index*20+4,bytes(8))
                    hdr.data_directories[11].VirtualAddress=0;hdr.data_directories[11].Size=0
                    _DUMP_STATE['restored_erased_import_names']=len(retained['name_patches'])
                    _DUMP_WARNINGS.append('Erased import names recovered from observed guest IAT bindings')
            if retained is not None:
                import struct
                for descriptor in retained['descriptors']:
                    for index,value in enumerate(descriptor['lookup_values']+[0]):
                        uc.mem_write(base_addr+descriptor['iat_rva']+index*4,struct.pack('<I',value))
                hdr.data_directories[1].VirtualAddress=retained['rva']
                hdr.data_directories[1].Size=retained['descriptor_bytes']
                _DUMP_STATE.update(import_method='validated_retained_table',restored_import_table_rva=retained['rva'],restored_import_symbols=retained['symbol_count'])
            else:
                recovered=None
                if getattr(sample.unpacker,'name','').lower()=='pecompact':
                    from unpacker.pe_rebuilder.bound_imports import rebuild_bound_imports
                    try:
                        recovered=rebuild_bound_imports(uc,base_addr,total_size,hdr.section_list,
                            dllname_to_functionlist,hdr.data_directories[1].VirtualAddress)
                    except (ValueError,UnicodeError) as exc:
                        _DUMP_STATE['bound_import_error']=f'{type(exc).__name__}: {str(exc)[:160]}'
                if recovered is not None:
                    hdr.data_directories[1].VirtualAddress=recovered['rva']
                    hdr.data_directories[1].Size=recovered['descriptor_bytes']
                    _DUMP_STATE.update(import_method='validated_bound_descriptors',bound_imports=recovered)
                else:
                    hdr = self.fix_imports(
                        uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, sample.original_imports
                    )
                    _DUMP_STATE['import_method']='backend_rebuild'

            if hdr is None:
                raise ValueError("fix_imports returned None")
        except Exception:
            _DUMP_WARNINGS.append("Import reconstruction failed; import directory removed")
            hdr.data_directories[1].VirtualAddress = 0
            hdr.data_directories[1].Size = 0

        directory=hdr.data_directories[1]
        importless=not (directory.VirtualAddress and directory.Size)
        if not importless:
            try:importless=bytes(uc.mem_read(base_addr+directory.VirtualAddress,20))==bytes(20)
            except (ValueError,IndexError):pass  # The unchanged final validator rejects malformed ranges.
        if getattr(sample,'_unpacker_generic_handoff',False) and importless:
            # The unchanged final gate rejects importless generic candidates.
            # Avoid section/checksum serialization of this already-rejected
            # state. Its key remains in the existing 1024-key/deadline bound;
            # it does not consume the 64 actual candidate-image attempts.
            raise _ImportsNotReady('No reconstructed import directory at handoff')

        hdr.data_directories[12].VirtualAddress = 0
        hdr.data_directories[12].Size = 0
        self.fix_sections(hdr, old_number_of_sections, virtualmemorysize)

        try:
            hdr.sync(uc)
        except Exception:
            _DUMP_WARNINGS.append("Header synchronization failed")
        hdr.opt_header.SizeOfImage = alignments(total_size, hdr.opt_header.SectionAlignment)
        hdr = self.fix_section_mem_protections(hdr, ntp)
        if _mark_handoff_section_executable(hdr):
            _DUMP_WARNINGS.append("Entry section execute permission inferred from emulator handoff; recovery remains partial")
        try:
            hdr.sync(uc)
            self.fix_checksum(uc, hdr, base_addr, total_size)
            hdr.sync(uc)
        except Exception:
            _DUMP_WARNINGS.append("Header synchronization failed")
        hdr.opt_header.DllCharacteristics = hdr.opt_header.DllCharacteristics & 0xFFBF
        try:
            hdr.sync(uc)
        except Exception:
            pass
        pe_write(uc, base_addr, total_size, path)

    def _dump_image_robust(self,uc,base_addr,virtualmemorysize,apicall_handler,sample,path="unpacked.exe"):
        if getattr(sample,'_unpacker_dump_started',False):
            _DUMP_STATE['suppressed_duplicate_dumps']=_DUMP_STATE.get('suppressed_duplicate_dumps',0)+1
            return
        from unpacker.image_snapshot import ImageSnapshot,handoff_rejection
        import copy
        from unicorn.x86_const import UC_X86_REG_EIP
        generic=getattr(sample,'_unpacker_generic_handoff',False)
        address=uc.reg_read(UC_X86_REG_EIP)
        rejected=getattr(sample,'_unpacker_rejected_handoffs',[])
        key=_handoff_key(sample,address)
        if key in getattr(sample,'_unpacker_rejected_keys',set()):
            sample._unpacker_rejected_handoff=True;return
        if len(getattr(sample,'_unpacker_rejected_keys',set()))>=1024:raise ValueError('Generic handoff key budget exceeded')
        if generic:
            restore_headers=False
            try:
                in_image=any(start<=address-base_addr<start+size for start,size,raw in _guest_section_layout(uc,base_addr))
            except Exception as exc:
                in_image=False;_DUMP_STATE['handoff_header_error']=f'{type(exc).__name__}: {str(exc)[:160]}'
            if not in_image:
                initial=sample.unpacker._handoff_initial_sections
                restore_headers=any(start<=address<start+size and start not in sample.unpacker._handoff_loader_sections
                    and raw==0 for start,size,raw in initial) and bool(getattr(sample,'_unpacker_import_epoch',0))
                if not restore_headers:
                    sample._unpacker_rejected_handoff=True
                    sample._unpacker_rejected_keys=getattr(sample,'_unpacker_rejected_keys',set())|{key}
                    _DUMP_STATE['skipped_non_image_handoffs']=_DUMP_STATE.get('skipped_non_image_handoffs',0)+1
                    return
        if generic and len(rejected)>=64:raise ValueError('Generic handoff candidate budget exceeded')
        warning_start=len(_DUMP_WARNINGS)
        snapshot=ImageSnapshot(uc,base_addr,_contiguous_image_span(uc,base_addr),_MAX_DUMP_BYTES)
        if generic and restore_headers:
            import struct
            initial_pe_offset=struct.unpack_from('<I',sample.loaded_image,60)[0]
            if not 4<=initial_pe_offset<=65536:raise ValueError('Invalid retained input PE header offset')
            size=struct.unpack_from('<I',sample.loaded_image,initial_pe_offset+24+60)[0]
            if not 64<=size<=65536 or size>len(sample.loaded_image):raise ValueError('Input header recovery exceeds bounds')
            snapshot.mem_write(base_addr,sample.loaded_image[:size])
            sample._unpacker_input_headers_restored=True
            _DUMP_WARNINGS.append('Live PE headers were erased; section layout restored from input metadata')
            _DUMP_STATE['input_headers_restored']=True
        # Upstream import append mutates descriptor objects as well as bytes.
        original_imports=sample.original_imports
        sample.original_imports=copy.deepcopy(original_imports)
        try:_dump_image_once(self,snapshot,base_addr,virtualmemorysize,apicall_handler,sample,path)
        except _ImportsNotReady:
            sample._unpacker_dump_started=False;sample._unpacker_rejected_handoff=True
            sample._unpacker_rejected_keys=getattr(sample,'_unpacker_rejected_keys',set())|{key}
            _DUMP_STATE['skipped_importless_handoffs']=_DUMP_STATE.get('skipped_importless_handoffs',0)+1
            del _DUMP_WARNINGS[warning_start:]
            return
        finally:sample.original_imports=original_imports
        if _DUMP_STATE.get('import_method')=='backend_rebuild' and Path(path).is_file():
            try:
                from unpacker.pe_rebuilder.imports import normalize_rebuilt_terminator
                data,facts=normalize_rebuilt_terminator(Path(path).read_bytes())
                Path(path).write_bytes(data);_DUMP_STATE['import_descriptor_termination']=facts
            except Exception as exc:
                _DUMP_WARNINGS.append('Rebuilt import descriptor termination could not be strictly validated')
                _DUMP_STATE['import_descriptor_error']=f'{type(exc).__name__}: {str(exc)[:160]}'
        if generic:
            candidate_facts={}
            reason=handoff_rejection(Path(path),candidate_facts)
            if reason:
                sample._unpacker_dump_started=False;sample._unpacker_rejected_handoff=True
                sample._unpacker_rejected_handoffs=[*rejected,address]
                sample._unpacker_rejected_keys=getattr(sample,'_unpacker_rejected_keys',set())|{key}
                records=_DUMP_STATE.setdefault('rejected_handoffs',[])
                records.append({'address':address,'reason':reason,'generation':list(key),'candidate_validation':candidate_facts})
                if len(records)>4:records[-5].pop('candidate_validation',None)
                del _DUMP_WARNINGS[warning_start:]
                output=Path(path)
                if output.is_file() and not output.is_symlink():output.unlink()

    ImageDump.dump_image = _dump_image_robust
    ImageDump.find_iat = _strict_find_iat
    # The pinned core imports merge by value. Its implementation seeds the
    # accumulator before sorting and loses writes below its first range.
    import unipacker.core as core
    from unpacker.write_ranges import merge_write_ranges
    core.merge = merge_write_ranges
    _PATCH_INSTALLED = True


def _configure_petite_unpacker(sample):
    """A jump within the initial loader section is not a section handoff.

    The pinned backend starts its allowed range at the entry instruction,
    incorrectly treating earlier instructions in the same section as an exit.
    Keep its allocation handling and dump implementation; fix only this range.
    """
    if sample.unpacker.name != 'PEtite':
        return None
    base = sample.opt_header.ImageBase
    entry = sample.opt_header.AddressOfEntryPoint
    sections = [section for section in sample.sections
                if section.VirtualAddress <= entry < section.VirtualAddress + section.VirtualSize]
    if len(sections) != 1:
        raise ValueError('PEtite entry must map to one loader section')
    section = sections[0]
    if not (0 <= base < 2**32 and section.VirtualAddress >= 4096
            and 0 < section.VirtualSize <= _MAX_DUMP_BYTES
            and base + section.VirtualAddress + section.VirtualSize <= 2**32):
        raise ValueError('PEtite loader section exceeds PE32 bounds')
    bounds = (base + section.VirtualAddress, base + section.VirtualAddress + section.VirtualSize - 1)
    sample.unpacker.allowed_addr_ranges = [bounds]
    return bounds


def _configure_generic_unpacker(sample):
    """Seed actual initial section bounds instead of dumping at instruction one."""
    if sample.unpacker.name not in {'unknown','PECompact'}:return False
    from unipacker.imagedump import ImportRebuilderDump
    unpacker=sample.unpacker
    sample._unpacker_generic_handoff=True
    base=sample.opt_header.ImageBase
    unpacker._handoff_image_sections=tuple((base+section.VirtualAddress,section.VirtualSize,section.SizeOfRawData) for section in sample.sections)
    unpacker._handoff_initial_sections=list(unpacker._handoff_image_sections)
    unpacker._handoff_original_raw={base+section.VirtualAddress:section.SizeOfRawData for section in sample.sections}
    unpacker._handoff_loader_sections=set()
    unpacker.allowed_addr_ranges=[(base+section.VirtualAddress,base+section.VirtualAddress+section.VirtualSize-1)
        for section in sample.sections if (section.SizeOfRawData>0 or section.Name in unpacker.allowed_sections) and section.VirtualSize>0]
    unpacker.section_hopping_control=bool(unpacker.allowed_addr_ranges)
    unpacker.write_execute_control=True
    unpacker.dumper=ImportRebuilderDump()
    return True


def _generic_handoff_eligible(unpacker,address,write_targets,resolved):
    sections=unpacker._handoff_image_sections
    cached=getattr(unpacker,'_handoff_cached_loader',None)
    if cached is not None and cached[0] is sections:
        start,size,raw=cached[1]
        if start<=address<start+size and start in unpacker._handoff_loader_sections:
            return address>=start+raw
    for section in sections:
        start,size,raw=section
        if start<=address<start+size:
            # Only cache immutable layouts. Guest header refresh replaces the
            # tuple, invalidating this identity check before the next decision.
            if isinstance(sections,tuple):unpacker._handoff_cached_loader=(sections,section)
            # Loader classification is monotonic for this section. Neither a
            # later write nor an import resolution can remove it, so preserve
            # the same raw-boundary decision without scanning every write.
            if start in unpacker._handoff_loader_sections:
                return address>=start+raw
            written=any(lower<=address<=upper for lower,upper in write_targets)
            if address<start+min(raw,size) and not written and not resolved:
                unpacker._handoff_loader_sections.add(start)
            return start not in unpacker._handoff_loader_sections or address>=start+raw
    return False


def _refresh_handoff_sections(uc,sample):
    """Accept bounded section extents restored by the guest, retaining stub bounds."""
    sections=[]
    for start,size,file_size in _guest_section_layout(uc,sample.BASE_ADDR):
        original_raw=sample.unpacker._handoff_original_raw.get(sample.BASE_ADDR+start,file_size)
        sections.append((sample.BASE_ADDR+start,size,min(original_raw,file_size)))
    # Packers can erase headers while the decompressed code remains in the
    # original zero-raw-data ranges. Retain those bounded input reservations.
    for start,size,raw in sample.unpacker._handoff_initial_sections:
        if raw==0 and size>0 and not any(lo<start+size and start<lo+length for lo,length,_ in sections):
            sections.append((start,size,0))
    sections.sort()
    sample.unpacker._handoff_image_sections=tuple(sections)
    sample._unpacker_live_header_updates=getattr(sample,'_unpacker_live_header_updates',0)+1


def _write_engine_progress(engine,path):
    data={'instructions':getattr(engine,'_unpacker_instructions',0),
          'last_address':getattr(engine,'_unpacker_last_address',None),
          'api_calls':{str(k):v for k,v in list(engine.apicall_counter.items())[:128]},
          'sections_executed':{str(k):v for k,v in list(engine.sections_executed.items())[:64]},
          'cpu_state':_failure_cpu_state(engine)}
    tracker=getattr(engine,'_unpacker_write_tracker',None)
    if tracker is not None:data['write_tracking']=tracker.metadata()
    module_model=getattr(engine,'_unpacker_module_model',None)
    if module_model is not None:data['module_handles']=module_model.facts()
    desktop=getattr(engine,'_unpacker_desktop_modules',None)
    if desktop is not None:data['resident_export_views']=desktop.facts()
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='progress-',delete=False) as output:
        json.dump(data,output);temporary=output.name
    os.replace(temporary,path)


def _observed_engine(base_engine,generic_configured,progress_path):
    class Observed(base_engine):
        def hook_code(self,uc,address,size,user_data):
            try:
                self._unpacker_instructions=getattr(self,'_unpacker_instructions',0)+1
                self._unpacker_last_address=address
                if self._unpacker_instructions&0xffff==0:_write_engine_progress(self,progress_path)
                dispatcher=getattr(self,'_unpacker_seh_dispatcher',None)
                if dispatcher is not None and (dispatcher.active or getattr(dispatcher,'has_instruction_state',False) or getattr(dispatcher,'requires_instruction_observation',False)) and hasattr(dispatcher,'observe_instruction'):
                    if dispatcher.observe_instruction(address,size):return
                # The profile's reserved model DLL slots are 0x61000000..62000000.
                # Ordinary specimen instructions avoid extra Python dispatch;
                # copied UD2 markers have invalid size in pinned Unicorn 1.x.
                if not 1<=size<=15 or 0x61000000<=address<0x62000000:
                    modules=getattr(self,'_unpacker_desktop_modules',None)
                    if modules is not None and modules.is_dispatch_site(uc,address,size):
                        section=self.sample.unpacker.get_section(address)
                        self.sections_executed[section]=self.sections_executed.get(section,0)+1
                        return  # CPU interprets the trap or guest interposition.
                if generic_configured:
                    self.sample._unpacker_rejected_handoff=False
                    if getattr(self.sample,'_unpacker_headers_dirty',False):
                        self.sample._unpacker_headers_dirty=False
                        try:_refresh_handoff_sections(uc,self.sample)
                        except Exception:pass  # Keep last validated extents during a header write sequence.
                    self.sample._unpacker_import_epoch=self.apicall_counter.get('GetProcAddress',0)
                    eligible=_generic_handoff_eligible(self.sample.unpacker,address,self.write_targets,
                        bool(self.apicall_counter.get('GetProcAddress',0)))
                    eligible=eligible and _handoff_key(self.sample,address) not in getattr(self.sample,'_unpacker_rejected_keys',set())
                    if getattr(self,'_unpacker_seh_active',False):eligible=False
                    self.sample.unpacker.write_execute_control=eligible
                    self.sample.unpacker.section_hopping_control=eligible
                return super().hook_code(uc,address,size,user_data)
            except Exception as exc:
                # Old Unicorn ctypes callbacks swallow Python exceptions. Stop
                # explicitly so unsupported semantics cannot continue execution.
                self._unpacker_callback_error=f'{type(exc).__name__}: {str(exc)[:240]}'
                self.stop()

        def hook_mem_invalid(self,uc,access,address,size,value,user_data):
            self._unpacker_memory_fault={'access':access,'address':address,'size':size}
            return super().hook_mem_invalid(uc,access,address,size,value,user_data)

        def hook_mem_access(self,uc,access,address,size,value,user_data):
            try:
                from unicorn import UC_MEM_WRITE
                dispatcher=getattr(self,'_unpacker_seh_dispatcher',None)
                if dispatcher is not None:dispatcher.check_context_access(address,size,writing=(access==UC_MEM_WRITE))
                if generic_configured and access==UC_MEM_WRITE and size>0:
                    if address<self.sample.BASE_ADDR+4096 and address+size>self.sample.BASE_ADDR:
                        self.sample._unpacker_headers_dirty=True
                    # A loader writing another page invalidates that page's rejected
                    # candidate. Its own self-modifying loop is not a new handoff.
                    code_page=getattr(self,'_unpacker_last_address',0)//_PAGE
                    writes=getattr(self.sample,'_unpacker_external_writes',{})
                    for page in range(address//_PAGE,(address+size-1)//_PAGE+1):
                        if page!=code_page and self.sample.BASE_ADDR<=page*_PAGE<self.sample.BASE_ADDR+_MAX_DUMP_BYTES:
                            writes[page]=writes.get(page,0)+1
                    self.sample._unpacker_external_writes=writes
                if access==UC_MEM_WRITE:
                    # Equivalent write branch for the pinned Unipacker 1.0.8;
                    # retain its stats, logs and breakpoints without re-sorting
                    # every previous range on every guest write.
                    tracker=getattr(self,'_unpacker_write_tracker',None)
                    if tracker is None or self.write_targets is not tracker.ranges:
                        tracker=WriteRangeTracker(self.write_targets)
                        self._unpacker_write_tracker=tracker
                    self.write_targets=tracker.add(address,size)
                    section=self.sample.unpacker.get_section(address)
                    self.sections_written[section]=self.sections_written.get(section,0)+1
                    if self.log_mem_write:
                        print(">>> Memory is being WRITTEN at 0x%x, data size = %u, data value = 0x%x" % (address,size,value))
                    if any(lower<=address<=upper for lower,upper in self.mem_breakpoints):
                        print(f"Memory breakpoint hit! Access WRITE to 0x{address:02x}")
                        self.pause()
                    return
                return super().hook_mem_access(uc,access,address,size,value,user_data)
            except Exception as exc:
                self._unpacker_callback_error=f'{type(exc).__name__}: {str(exc)[:240]}'
                self.stop()
    return Observed


def _optional_import_parser(base_parser):
    class ImportOptional(base_parser):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            if not hasattr(self,'DIRECTORY_ENTRY_IMPORT'):
                directory=self.OPTIONAL_HEADER.DATA_DIRECTORY[1]
                if directory.VirtualAddress or directory.Size:raise ValueError('Malformed nonempty input import directory')
                self.DIRECTORY_ENTRY_IMPORT=[]
    return ImportOptional


def _failure_cpu_state(engine):
    """Small read-only guest-state record, emitted only after a failed run."""
    try:
        from unicorn import x86_const
        uc=engine.uc
        names=['EIP','ESP','EBP','EAX','EBX','ECX','EDX','ESI','EDI','EFLAGS']
        registers={name:uc.reg_read(getattr(x86_const,'UC_X86_REG_'+name)) for name in names}
        regions=list(uc.mem_regions());pc=registers['EIP']
        available=next((min(32,hi-pc+1) for lo,hi,perm in regions if lo<=pc<=hi),0)
        return {'registers':registers,'instruction_bytes':bytes(uc.mem_read(pc,available)).hex() if available else '',
                'mapped_regions':[list(region) for region in regions[:32]],'regions_truncated':len(regions)>32}
    except Exception:return {'capture':'unavailable'}


def _exception_dispatcher(engine,name,generic):
    if name=='PECompact':
        from unpacker.guest_seh import AccessViolationDispatcher
        return AccessViolationDispatcher(engine)
    if name=='PEtite' or generic:
        from unpacker.stack_exceptions import StackExceptionDispatcher
        dispatcher=StackExceptionDispatcher(engine,access_violations=True)
        if name=='PEtite':dispatcher.MAX_FAULTS=8;dispatcher.profile_scope='PEtite'
        return dispatcher
    return None


def run_unipacker_emulation(sample_path, out_path, options, packer_label="unipacker"):
    from unpacker.backend_worker import supervise
    if not options.allow_emulation:
        return UnpackResult(False,error="Emulation disabled; explicitly opt in inside an isolated environment",status="unsupported")
    return supervise("unipacker",sample_path,out_path,options,packer_label)


def _run_unipacker_in_process(sample_path, out_path, options, packer_label):
    """Private entry point for the supervised child process only."""
    global _MAX_DUMP_BYTES, _MISSING_READ_BYTES
    _MAX_DUMP_BYTES = options.max_output_size_mb * 1024 * 1024
    _MISSING_READ_BYTES = 0
    _DUMP_WARNINGS.clear()
    _DUMP_STATE.clear()
    from unpacker.detector.format_ import load_pe
    pe = load_pe(sample_path)
    if pe is None:
        return UnpackResult(False,error="Unipacker requires a valid PE32 file",status="unsupported")
    try:
        if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
            return UnpackResult(False,error="Unipacker supports x86 PE32 only",status="unsupported")
        input_imports=bool(getattr(pe,"DIRECTORY_ENTRY_IMPORT",None))
        if not input_imports:
            directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
            if directory.VirtualAddress or directory.Size:
                return UnpackResult(False,error="Nonempty input import directory is malformed; custom loader needed",status="unsupported")
    finally:
        pe.close()
    if out_path.exists() or out_path.is_symlink():
        return UnpackResult(False,error="Output collision")
    error = unipacker_import_error()
    if error:
        return UnpackResult(False,error=f"Unipacker import failed: {error}. {UNIPACKER_INSTALL_HINT}",status="dependency_error")
    from unipacker.core import Sample, UnpackerEngine, SimpleClient
    log = []
    error = None
    generic_configured=False
    petite_loader_range=None
    engine=None
    api_model=None
    seh_dispatch=None
    try:
        sample = Sample(str(sample_path),auto_default_unpacker=True)
        log.append(f"Unipacker identified: {sample.unpacker.name}")
        petite_loader_range = _configure_petite_unpacker(sample)
        generic_configured=_configure_generic_unpacker(sample)
        install_unipacker_patch()
        engine_class=_observed_engine(UnpackerEngine,generic_configured,options.output_dir/".emulation-progress.json")
        if input_imports:
            engine = engine_class(sample,str(out_path))
        else:
            import pefile
            parser=pefile.PE
            try:
                pefile.PE=_optional_import_parser(parser)
                engine=engine_class(sample,str(out_path))
            finally:pefile.PE=parser
        if getattr(engine,'uc',None) is not None:
            original_start=engine.uc.emu_start
            def observed_start(*args,**kwargs):
                from unicorn import UcError
                while True:
                    try:
                        engine._unpacker_inside_emulation=True
                        try:value=original_start(*args,**kwargs)
                        finally:engine._unpacker_inside_emulation=False
                        resume=api_model.protection.take_resume(engine.uc) if api_model is not None else None
                        if resume is not None:
                            args=(resume,*args[1:]);continue
                        resume=seh_dispatch.take_resume() if seh_dispatch is not None else None
                        if resume is not None:
                            args=(resume,*args[1:]);continue
                        handler=seh_dispatch.arm() if seh_dispatch is not None else None
                        if handler is not None:
                            args=(handler,*args[1:]);continue
                        return value
                    except UcError as exc:
                        if seh_dispatch is not None:seh_dispatch.capture_cpu_error(exc)
                        handler=seh_dispatch.arm() if seh_dispatch is not None else None
                        if handler is not None:
                            args=(handler,*args[1:]);continue
                        engine._unpacker_cpu_error=f'{type(exc).__name__}: {str(exc)[:240]}'
                        raise
            engine.uc.emu_start=observed_start
        if hasattr(engine,'apicall_handler'):
            from unpacker.winapi_model import SelfFileModel
            from unipacker.apicalls import apicall_mapping
            api_model=SelfFileModel(engine,sample_path.read_bytes(),options.max_input_size_mb*1024*1024)
            engine._unpacker_module_model=api_model.modules
            api_model.yesno_answer=options.extra.get("guest_yesno_answer","no")
            if type(api_model.yesno_answer) is not str or api_model.yesno_answer not in {"yes","no"}:raise ValueError("Invalid guest YES/NO policy")
            api_model.install(apicall_mapping)
            from unpacker.loader_lists import install_loader_lists
            engine._unpacker_loader_lists=install_loader_lists(engine)
            profile=options.extra.get('guest_module_profile','named-exports')
            if profile not in {'named-exports','core-strict'}:raise ValueError('Invalid guest module profile')
            if profile=='named-exports':
                from unpacker.guest_desktop_modules import DesktopModules
                api_model.desktop_modules=DesktopModules(api_model)
                engine._unpacker_desktop_modules=api_model.desktop_modules
            seh_dispatch=_exception_dispatcher(engine,sample.unpacker.name,generic_configured)
            if seh_dispatch is not None:engine._unpacker_seh_dispatcher=seh_dispatch
            if generic_configured and sample.unpacker.name!='PECompact':
                from unpacker.core_import_bindings import bind_initial_module_handle
                engine._unpacker_core_import_bindings=bind_initial_module_handle(engine,sample_path.read_bytes())
                from unpacker.core_import_bindings import install_modeled_core_exports
                engine._unpacker_core_import_bindings['resident_api_entries']=install_modeled_core_exports(engine,api_model)
        engine.register_client(SimpleClient(threading.Event()))
        # Upstream pause() waits for an interactive resume after dumping. In a
        # batch worker this must terminate the engine, not wait indefinitely.
        def batch_pause():
            if not getattr(sample,'_unpacker_rejected_handoff',False):engine.stop()
        engine.pause = batch_pause
        engine.emu()
        if hasattr(engine,"apicall_counter"):_write_engine_progress(engine,options.output_dir/".emulation-progress.json")
    except Exception as exc:
        error = f"Emulation/initialization error: {type(exc).__name__}: {str(exc)[:240]}"
    if engine is not None:
        cpu_error=getattr(engine,'_unpacker_cpu_error',None)
        if cpu_error:error=error or 'Emulated CPU stopped: '+cpu_error
        callback_error=getattr(engine,'_unpacker_callback_error',None)
        memory_fault=getattr(engine,'_unpacker_memory_fault',None)
        if callback_error:error=error or 'Emulation callback stopped: '+callback_error
        if memory_fault:error=error or 'Unmapped emulated memory access: '+str(memory_fault)
    has_output=out_path.is_file() and not out_path.is_symlink() and out_path.stat().st_size>0
    if not has_output and api_model is not None and api_model.guest_exit_code is not None:
        error=error or f'Guest ExitProcess(0x{api_model.guest_exit_code:08x}) before reconstruction handoff'
    if seh_dispatch is not None and seh_dispatch.unsupported:
        error='Unsupported guest exception: '+seh_dispatch.unsupported
    metadata = {"method":packer_label,"missing_read_bytes":_MISSING_READ_BYTES,
                "repairs":list(_DUMP_WARNINGS),"complete_recovery":"not_established","input_has_imports":input_imports,**_DUMP_STATE}
    if seh_dispatch is not None:metadata['seh']=seh_dispatch.facts()
    if api_model is not None:
        metadata['file_io']=api_model.file_io.facts()
        metadata['file_attributes']=api_model.file_attributes.facts()
        metadata['mutexes']=api_model.mutexes.facts()
        metadata['heap_policy']=api_model.heap_policy.facts()
    if engine is not None and hasattr(engine,'_unpacker_core_import_bindings'):
        metadata['core_import_bindings']=engine._unpacker_core_import_bindings
    if engine is not None and petite_loader_range is not None:
        metadata['petite_loader_range'] = list(petite_loader_range)
    if api_model is not None:
        if not has_output or error:
            metadata['guest_exit_code']=api_model.guest_exit_code
            metadata['last_guest_message']=api_model.last_message
        if api_model.callbacks.frames and out_path.is_file():
            api_model.warnings.append('Guest initializer callbacks are pending at dump handoff')
        metadata['api_model']={'scope':'in_memory_specimen_only','events':api_model.events,'unsupported':api_model.unsupported,'warnings':api_model.warnings,
            'page_protection':api_model.protection.metadata(),
            'registered_messages':{'scope':'isolated_guest_session','names':len(api_model.registered_messages.names),
                'name_profile':'ascii','max_names':api_model.registered_messages.MAX_NAMES,'max_characters':255},
            'screen_dc':api_model.display.metadata(),
            'formatted_output':{'profile':'bounded_ansi_integer_wsprintfA','calls':api_model.guest_format.calls,
                'max_bytes_including_nul':1024,'max_arguments':32,'floating_wide_and_writeback_formats':'unsupported'},
            'mapped_module_handles':api_model.modules.facts(),
            'resident_export_views':api_model.desktop_modules.facts() if api_model.desktop_modules is not None else {'profile':'core-strict'},
            'desktop_profile':{'dpi':96,'large_icon_pixels':[32,32],'scrollbar_pixels':[17,17],'supported_metrics':sorted(api_model.desktop_metrics),
                'window_objects':'not_implemented','source':'fixed_guest_configuration'},
            'dialog_policy':{'yesno_answer':api_model.yesno_answer,'source':'explicit_worker_configuration'},
            'profile':{'windows_version':'6.1.7601','ansi_code_page':1252,'environment':'empty','command_line':r'C:\sample.bin','threads':1,'crt_locale':'C','crt_abi':'legacy_msvcrt_pe32'},
            'exception_filter':api_model.exception_filter,'exception_dispatch':('bounded_software_traps' if seh_dispatch.software_traps else 'bounded_pecompact_seh') if seh_dispatch is not None else 'not_implemented',
            'crt_exit':{'registered_callbacks':len(api_model.crt_startup.exit_callbacks),'dispatch':'not_implemented'},
            'guest_callbacks':{'calls':api_model.callbacks.calls,'completed_tables':api_model.callbacks.completed,'pending_tables':len(api_model.callbacks.frames)}}
        _DUMP_WARNINGS.extend(api_model.warnings)
        metadata['repairs']=list(_DUMP_WARNINGS)
        if api_model.unsupported:
            metadata['unsupported_api']=api_model.unsupported[-1]
            # An intentional model stop can also surface as Unicorn's invalid
            # instruction at the trap. Preserve the explicit semantic cause.
            error=api_model.unsupported[-1]['name']+': '+api_model.unsupported[-1]['reason']
    if engine is not None and hasattr(engine,'_unpacker_write_tracker'):metadata['write_tracking']=engine._unpacker_write_tracker.metadata()
    if engine is not None and hasattr(engine,'_unpacker_loader_lists'):metadata['loader_lists']=engine._unpacker_loader_lists
    metadata["generic_handoff_configured"]=generic_configured
    if engine is not None:metadata['live_header_updates']=getattr(getattr(engine,'sample',None),'_unpacker_live_header_updates',0)
    if generic_configured:
        metadata['handoff_state']={'sections':[list(section) for section in sample.unpacker._handoff_image_sections[:32]],
            'loader_starts':sorted(sample.unpacker._handoff_loader_sections)[:32],
            'dump_started':getattr(sample,'_unpacker_dump_started',False)}
    if engine is not None and hasattr(engine,"sections_executed"):
        metadata["sections_executed"]={str(key):value for key,value in list(engine.sections_executed.items())[:64]}
        metadata["api_calls"]={str(key):value for key,value in list(engine.apicall_counter.items())[:128]}
        if error:metadata['failure_cpu_state']=_failure_cpu_state(engine)
    warnings = list(_DUMP_WARNINGS)
    if _MISSING_READ_BYTES:
        warnings.append("Unreadable memory was replaced with zeros")
    if not has_output:
        return UnpackResult(False,log=log,error=error or "No current-run output",status="unsupported" if (api_model is not None and api_model.unsupported) or (seh_dispatch is not None and seh_dispatch.unsupported) else "failed",metadata=metadata)
    partial = error is not None or bool(warnings)
    return UnpackResult(not partial,output_path=out_path,log=log,error=error or ("Degraded emulation dump" if partial else None),
        status="partial" if partial else "completed",artifact_kind="reconstructed_pe",warnings=warnings,metadata=metadata)


def unipacker_import_error() -> str | None:
    """Report real import/core-integrity failures from the selected runtime.

    The reviewed release uses a separately versioned Unicorn compatibility
    build. No host setuptools activation or global import shims are applied.
    """
    try:
        from unipacker.core import Sample, UnpackerEngine, SimpleClient  # noqa: F401
    except Exception as exc:  # pragma: no cover - exact failure mode varies by environment
        return f"{type(exc).__name__}: {exc}"
    return None


def unipacker_available() -> bool:
    return unipacker_import_error() is None
