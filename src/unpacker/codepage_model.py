"""Bounded guest string conversion for explicit CP1252 and UTF-8 profiles."""


class CodePages:
    def __init__(self,model):self.model=model

    def wide_to_multi(self,uc,codepage,flags,source,count,destination,capacity,default,used):
        m=self.model
        if codepage==0:codepage=1252
        if codepage not in {1252,65001} or not source or not count:
            m.last_error=87;return 0
        if flags&~(0x400 if codepage==1252 else 0x80):m.last_error=1004;return 0
        if codepage==65001 and (default or used):m.last_error=87;return 0
        if capacity>65536 or (capacity and not destination) or source==destination:
            m.last_error=87;return 0
        if count==0xffffffff:
            raw=bytearray()
            for offset in range(32768):
                pair=uc.mem_read(source+offset*2,2)
                if len(pair)!=2:m.reject('WideCharToMultiByte','Truncated guest UTF-16')
                raw+=pair
                if pair==b'\0\0':break
            else:m.reject('WideCharToMultiByte','Guest string budget exceeded')
        elif 0<count<=32768:
            raw=uc.mem_read(source,count*2)
            if len(raw)!=count*2:m.reject('WideCharToMultiByte','Truncated guest UTF-16')
        else:m.last_error=87;return 0
        try:text=bytes(raw).decode('utf-16le','strict' if flags&0x80 else 'replace')
        except UnicodeDecodeError:m.last_error=1113;return 0
        substituted=False
        if codepage==65001:encoded=text.encode('utf-8')
        else:
            try:encoded=text.encode('cp1252')
            except UnicodeEncodeError:
                if not flags&0x400:m.reject('WideCharToMultiByte','CP1252 best-fit substitution is not modeled')
                replacement=bytes(uc.mem_read(default,1)) if default else b'?'
                if len(replacement)!=1:m.reject('WideCharToMultiByte','Invalid default character')
                chunks=[]
                for character in text:
                    try:chunks.append(character.encode('cp1252'))
                    except UnicodeEncodeError:chunks.append(replacement);substituted=True
                encoded=b''.join(chunks)
        if used:uc.mem_write(used,int(substituted).to_bytes(4,'little'))
        if not capacity:return len(encoded)
        if capacity<len(encoded):m.last_error=122;return 0
        uc.mem_write(destination,encoded);return len(encoded)
