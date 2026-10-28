"""Detached bounded guest-image bytes for reconstruction without mutating the CPU."""


class ImageSnapshot:
    def __init__(self,uc,base,size,limit):
        if not 0<size<=limit:raise ValueError('Snapshot exceeds image budget')
        self.base=base;self.data=bytearray(uc.mem_read(base,size));self.cpu=uc
        if len(self.data)!=size:raise ValueError('Truncated image snapshot')

    def _offset(self,address,size):
        offset=address-self.base
        if size<0 or offset<0 or offset+size>len(self.data):raise ValueError('Reconstruction access escapes image snapshot')
        return offset

    def mem_read(self,address,size):
        # Unipacker's ctypes PE parser requires a writable, detached buffer.
        offset=self._offset(address,size);return bytearray(self.data[offset:offset+size])

    def mem_write(self,address,value):
        offset=self._offset(address,len(value));self.data[offset:offset+len(value)]=value

    def reg_read(self,register):return self.cpu.reg_read(register)
    def mem_regions(self):return self.cpu.mem_regions()


def handoff_rejection(path,diagnostics=None):
    """Reference-free rejection of clearly premature generic image dumps."""
    import pefile
    from unpacker.reconstruction import entry_mapping,import_iat_consistency
    if not path.is_file():return 'No parseable image at candidate handoff'
    try:
        pe=pefile.PE(str(path),fast_load=False)
        try:
            mapping=entry_mapping(pe)
            if diagnostics is not None:diagnostics['entry']=mapping
            if not mapping['file_backed'] or not mapping['executable']:return 'Candidate entry is not file-backed executable data'
            imports=getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])
            if not imports or not any(descriptor.imports for descriptor in imports):return 'Candidate has no reconstructed imports'
            iat=import_iat_consistency(pe,include_details=diagnostics is not None)
            if diagnostics is not None:diagnostics['iat']=iat
            if not iat['passed']:return 'Candidate IAT is not loader-ready'
            return None
        finally:pe.close()
    except (pefile.PEFormatError,ValueError,IndexError):return 'Candidate PE headers are invalid'
