"""Bounded read-only metadata and authenticated payload parsing for pakkero.

Profile: ELF64/LSB Go string-header metadata, SHA512/256 prefix key, reversed
AES-GCM bytes, zlib/base64 ELF payload. No launcher instructions are executed.
"""
import base64,hashlib,re,struct,zlib
from unpacker.elf_notes import bounded_elf

MAX_BYTES=32*1024*1024
MAX_HEADERS=4096
MAX_CANDIDATES=128
ALPHABET=frozenset('0OÓÕÔÒÖŌŎŐƠΘΟ')
REVERSE_BITS=bytes(int(f'{x:08b}'[::-1],2) for x in range(256))


def elf64_loads(data):
    if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01':raise ValueError('Supported carrier requires ELF64/LSB')
    fields=struct.unpack_from('<HHIQQQIHHHHHH',data,16)
    off,size,count=fields[4],fields[8],fields[9]
    if fields[0] not in {2,3} or fields[1]!=62 or fields[2]!=1 or fields[7]!=64 or size!=56 or not 1<=count<=128 or off+size*count>len(data):
        raise ValueError('Invalid carrier program-header profile')
    parts=[]
    for index in range(count):
        kind,flags,start,va,pa,length,memsz,align=struct.unpack_from('<IIQQQQQQ',data,off+index*size)
        if start+length>len(data):raise ValueError('Carrier segment exceeds file')
        if kind==1:
            if length>memsz or va+length>2**64:raise ValueError('Invalid carrier load segment')
            parts.append((va,va+length,start))
    if not parts:raise ValueError('Carrier has no load segments')
    return off+size*count,parts


def upx_carrier(data,limit):
    """Restore only a repeated signature, requiring a unique checked header."""
    if not 64<=len(data)<=min(limit,MAX_BYTES):raise ValueError('Pakkero input exceeds profile budget')
    end,parts=elf64_loads(data)
    if end+12>len(data):raise ValueError('Missing UPX loader metadata')
    signature=data[end+4:end+8]
    if signature==bytes(4):raise ValueError('Ambiguous zero carrier signature')
    positions=[m.start() for m in re.finditer(re.escape(signature),data)]
    if not 1<=len(positions)<=8:raise ValueError('Repeated carrier signature count is unsupported')
    candidates=[]
    for pos in positions:
        h=data[pos:pos+32]
        if len(h)==32 and h[4] in {10,11,12,13,14} and h[4]==data[end+10] and h[5]==data[end+11]==22 and sum(h[4:31])%251==h[31]:
            size=struct.unpack_from('<I',h,24)[0]
            if end+12<pos and pos+36<=len(data) and 64<=size<=min(limit,MAX_BYTES):candidates.append((pos,size))
    if len(candidates)!=1:raise ValueError('No unique checksummed supported UPX carrier header')
    pos,size=candidates[0]
    return data[:pos+36].replace(signature,b'UPX!'),{'carrier_end':pos+36,'declared_launcher_bytes':size,
        'signature_replacements':sum(start<pos+36 for start in positions),'header_offset':pos}


def numeric_offsets(launcher,carrier_end,input_size):
    if len(launcher)>MAX_BYTES:raise ValueError('Decoded launcher exceeds profile budget')
    _,parts=elf64_loads(launcher);headers={}
    for off in range(0,len(launcher)-15,8):
        address,size=struct.unpack_from('<QQ',launcher,off)
        if not 1<=size<=256:continue
        positions=[start+address-lo for lo,hi,start in parts if lo<=address and address+size<=hi]
        if len(positions)!=1:continue
        value=launcher[positions[0]:positions[0]+size]
        try:text=value.decode('utf8')
        except UnicodeDecodeError:continue
        if text and set(text)<=ALPHABET:
            if len(headers)>=MAX_HEADERS:raise ValueError('Go string-header budget exceeded')
            headers[off]=len(text)
    offsets=set()
    for off in sorted(headers):
        if 48<=headers.get(off-16,0)<=57:continue
        values=[];pos=off
        while 48<=headers.get(pos,0)<=57:
            values.append(chr(headers[pos]));pos+=16
        if 5<=len(values)<=8:
            value=int(''.join(values))
            if carrier_end<value<input_size-28:offsets.add(value)
        if len(offsets)>MAX_CANDIDATES:raise ValueError('Numeric offset candidate budget exceeded')
    if not offsets:raise ValueError('Supported Go Unicode offset metadata is absent')
    return sorted(offsets)


def padding_size(offset):
    # Positive Go signed-varint => first encoded byte is even. Reversing
    # its bits clears the continuation bit; decoding therefore ends there.
    value=REVERSE_BITS[((offset<<1)&127)|128]
    return (value>>1)+1 if value&1 else value>>1


def decode_payload(data,launcher,carrier_end,limit):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    candidates=numeric_offsets(launcher,carrier_end,len(data));results=[]
    for off in candidates:
        pad=padding_size(off)
        if not 28<len(data)-pad-off<=min(MAX_BYTES,limit):continue
        cipher=data[off:len(data)-pad][::-1].translate(REVERSE_BITS)
        key=hashlib.new('sha512_256',data[:off]).digest()
        try:plain=AESGCM(key).decrypt(cipher[:12],cipher[12:],None)
        except InvalidTag:continue
        maximum=4*((limit+2)//3)
        decoder=zlib.decompressobj()
        try:encoded=decoder.decompress(plain,maximum+1)
        except zlib.error as exc:raise ValueError('Authenticated payload zlib stream is invalid') from exc
        if len(encoded)>maximum or not decoder.eof or decoder.unused_data:raise ValueError('Authenticated payload zlib bounds/termination failed')
        payload=base64.b64decode(encoded,validate=True)
        if not 64<=len(payload)<=limit:raise ValueError('Decoded payload exceeds output budget')
        elf=bounded_elf(payload);loads=[]
        for segment in elf.iter_segments():
            if segment['p_offset']+segment['p_filesz']>len(payload):raise ValueError('Payload segment escapes file')
            if segment['p_type']=='PT_LOAD':
                if segment['p_filesz']>segment['p_memsz']:raise ValueError('Payload segment exceeds memory size')
                loads.append(segment)
        if not any(s['p_flags']&1 and s['p_vaddr']<=elf.header['e_entry']<s['p_vaddr']+s['p_filesz'] for s in loads):
            raise ValueError('Payload entry is not file-backed executable data')
        results.append((payload,{'payload_offset':off,'padding_bytes':pad,'payload_bytes':len(payload),
            'numeric_candidates':len(candidates),'authentication':'AES-GCM-128bit-tag',
            'key_source':'SHA512/256 of unchanged input prefix','self_prefix_payload':payload==data[:off]}))
    if len(results)!=1:raise ValueError('No unique authenticated supported payload')
    return results[0]
