"""Pure guest path queries for a fixed C:\\ working directory.

This module never opens a path. Namespace, drive-state and DOS-name cases
outside the explicit profile stop rather than borrowing host path semantics.
"""
import ntpath
import struct


class GuestPaths:
    def __init__(self,model):
        self.model=model

    def upper_ascii(self,uc,buffer,count):
        # CharUpperBuffA consumes exactly cchLength bytes, including embedded
        # NUL bytes. Non-ASCII case mappings need a fuller Windows NLS profile.
        if not count:return 0
        if not buffer or count>self.model.limit or buffer+count>0x100000000:
            self.model.reject('CharUpperBuffA','Guest buffer exceeds PE32 address/budget bounds')
        value=bytes(uc.mem_read(buffer,count))
        if len(value)!=count or any(c>=128 for c in value):
            self.model.reject('CharUpperBuffA','Only complete ASCII buffers are modeled')
        uc.mem_write(buffer,value.upper())
        return count

    def full_path(self,uc,name,size,buffer,file_part):
        reject=lambda reason:self.model.reject('GetFullPathNameA',reason)
        if not name:reject('Null input path is outside the supported profile')
        value=self.model.string(uc,name).replace(b'/',b'\\')
        if not value or value.startswith(b'\\\\'):
            reject('Empty paths and UNC/device namespaces are unsupported')
        drive,tail=ntpath.splitdrive(value)
        if drive and drive.lower()!=b'c:':reject('Only the fixed guest C: drive is modeled')
        if any(c<32 or c in b'<>"|?*:' for c in tail):
            reject('Path syntax is outside the simple guest path profile')
        # Win32 trailing-dot/space and DOS device normalization needs its own
        # namespace model; do not silently substitute ntpath behavior for it.
        for part in tail.split(b'\\'):
            if part in {b'',b'.',b'..'}:continue
            stem=part.split(b'.',1)[0].upper()
            if part.endswith((b' ',b'.')) or stem in {b'CON',b'PRN',b'AUX',b'NUL'} or (
                len(stem)==4 and stem[:3] in {b'COM',b'LPT'} and stem[3:4] in b'123456789'):
                reject('DOS device and trailing-dot/space paths are unsupported')
        normalized=ntpath.normpath(b'C:\\'+tail.lstrip(b'\\'))
        if tail.endswith(b'\\') and not normalized.endswith(b'\\'):normalized+=b'\\'
        needed=len(normalized)+1
        if size>self.model.limit:reject('Output capacity exceeds the guest buffer budget')
        if size<needed:return needed
        if not buffer or buffer+needed>0x100000000 or file_part>0xfffffffc:
            reject('Output pointer is outside PE32 address space')
        uc.mem_write(buffer,normalized+b'\0')
        if file_part:
            basename=ntpath.basename(normalized)
            pointer=buffer+len(normalized)-len(basename) if basename else 0
            uc.mem_write(file_part,struct.pack('<I',pointer))
        if len(self.model.events)<32:
            self.model.events.append({'operation':'GetFullPathNameA','profile':'fixed_guest_c_drive_root',
                                      'output_bytes':len(normalized)})
        return len(normalized)
