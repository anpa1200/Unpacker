"""Bounded ANSI/integer wsprintfA profile, entirely within guest memory.

No host printf, locale, pointer dereference or format evaluation is used.
Unsupported format families fail before any output write.
"""
import re
import struct


class GuestFormat:
    LIMIT=1024
    ARGUMENTS=32
    SPEC=re.compile(rb'%([-0]*)([0-9]{0,4})(?:\.([0-9]{0,4}))?([hl]?)([cdiusxX%])')

    def __init__(self,model):self.model=model;self.calls=0

    def reject(self,reason):self.model.reject((self.model.current_call or {}).get('name','wsprintfA'),reason)

    def _read(self,uc,address,count):
        if not address or address+count>2**32 or not self.model.protection._cover(list(uc.mem_regions()),address,address+count,1):
            self.reject('Format/input argument is not readable bounded guest memory')
        return bytes(uc.mem_read(address,count))

    def _string(self,uc,address,maximum=None):
        result=bytearray();limit=self.LIMIT if maximum is None else maximum
        for index in range(limit):
            value=self._read(uc,address+index,1)
            if value==b'\0':return bytes(result)
            result.extend(value)
        if maximum is not None:return bytes(result)
        self.reject('Unterminated format/string exceeds 1024-byte profile')

    def format_a(self,uc,destination,format_pointer,arguments):
        source=self._string(uc,format_pointer);output=bytearray();cursor=0;consumed=0
        while cursor<len(source):
            if source[cursor]!=37:
                output.append(source[cursor]);cursor+=1
            else:
                match=self.SPEC.match(source,cursor)
                if match is None:self.reject('Format conversion is outside ANSI/integer profile')
                flags,width,precision,length,kind=match.groups();cursor=match.end()
                if flags not in {b'',b'-',b'0',b'-0'}:self.reject('Unsupported format flags')
                width=int(width or b'0');precision=int(precision or b'0') if precision is not None else None
                if width>=self.LIMIT or (precision is not None and precision>=self.LIMIT):self.reject('Format width/precision exceeds output budget')
                if kind==b'%':
                    if flags or width or precision is not None or length:self.reject('Modified percent conversion is unsupported')
                    output.extend(b'%');continue
                if consumed>=self.ARGUMENTS:self.reject('Variadic argument budget exceeded')
                value=struct.unpack('<I',self._read(uc,arguments+consumed*4,4))[0];consumed+=1
                if kind==b's':
                    if length==b'l':self.reject('Wide string conversion is outside ANSI profile')
                    field=self._string(uc,value,precision);sign=b''
                elif kind==b'c':
                    if length==b'l' or precision is not None or not value&255:self.reject('Wide/null/precision character conversion is unsupported')
                    field=bytes([value&255]);sign=b''
                else:
                    bits=16 if length==b'h' else 32;value&=(1<<bits)-1;sign=b''
                    if kind in {b'd',b'i'} and value&(1<<(bits-1)):
                        value=(1<<bits)-value;sign=b'-'
                    field=(format(value,'X' if kind==b'X' else 'x') if kind in {b'x',b'X'} else str(value)).encode('ascii')
                    if precision is not None:field=field.rjust(max(1,precision),b'0')
                if kind not in {b's',b'c'} and b'0' in flags and b'-' not in flags:
                    field=sign+field.rjust(max(0,width-len(sign)),b'0')
                else:field=sign+field
                output.extend(field.ljust(width,b' ') if b'-' in flags else field.rjust(width,b' '))
            if len(output)>=self.LIMIT:self.reject('Formatted output exceeds 1023 bytes plus terminator')
        if not destination or destination+len(output)+1>2**32 or not self.model.protection._cover(list(uc.mem_regions()),destination,destination+len(output)+1,2):
            self.reject('Output is not writable bounded guest memory')
        uc.mem_write(destination,bytes(output)+b'\0');self.calls+=1
        return len(output)
