"""Metadata of the supplied virtual sample, not a host filesystem fallback."""
import ntpath,struct


class VirtualFileAttributes:
    # Explicit guest-file configuration, independent of host/private timestamps.
    EPOCH_FILETIME=116444736000000000  # 1970-01-01 UTC in FILETIME units.
    def __init__(self,model):self.model=model;self.queries=0

    def query_w(self,uc,name_pointer,information_class,output):
        if information_class!=0:self.model.last_error=87;return 0
        if not name_pointer:self.model.last_error=87;return 0
        data=bytearray()
        for index in range(1024):
            try:unit=bytes(uc.mem_read(name_pointer+index*2,2))
            except Exception:self.model.reject('GetFileAttributesExW','Guest filename is not readable')
            if len(unit)!=2:self.model.reject('GetFileAttributesExW','Truncated guest filename')
            if unit==bytes(2):break
            data.extend(unit)
        else:self.model.reject('GetFileAttributesExW','Guest filename exceeds the bounded profile')
        try:name=data.decode('utf-16le')
        except UnicodeDecodeError:self.model.reject('GetFileAttributesExW','Malformed UTF-16 path is outside the profile')
        if len(name)>260 or name.startswith('\\\\') or (':' in name and not name.lower().startswith('c:')):
            self.model.reject('GetFileAttributesExW','Long/network/foreign-drive paths are outside the profile')
        name=ntpath.normpath(ntpath.join('C:\\',name.replace('/','\\'))).lower()
        if name=='c:\\':self.model.reject('GetFileAttributesExW','Directory metadata is not modeled')
        if name!=self.model.PATH.decode('ascii').lower():self.model.last_error=2 if ntpath.dirname(name)=='c:\\' else 3;return 0
        self.model.file_io._writable(uc,output,36,'GetFileAttributesExW')
        size=len(self.model.data);stamp=self.EPOCH_FILETIME
        uc.mem_write(output,struct.pack('<IQQQII',0x80,stamp,stamp,stamp,size>>32,size&0xffffffff))
        self.queries+=1;return 1

    def facts(self):
        return {'scope':'supplied_virtual_sample_only','queries':self.queries,
          'attributes':0x80,'timestamps':'explicit_fixed_guest_epoch_1970','host_metadata_access':False}
