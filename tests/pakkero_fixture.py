"""Construct memory-only format fixtures; neither launcher nor payload is run."""
import base64,hashlib,struct,zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def elf(length=4096):
    data=bytearray(length);data[:16]=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',data,16,2,62,1,0x400080,64,0,0,64,56,1,64,0,0)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x400000,0x400000,length,length,4096)
    data[128:131]=b'\x31\xc0\xc3'  # Benign return-zero bytes, never executed.
    return bytes(data)


def launcher(numbers=(100000,)):
    data=bytearray(elf(8192));slot=0x300;textpos=0x700
    for number in numbers:
        for digit in str(number):
            value=('Ó'*ord(digit)).encode()
            struct.pack_into('<QQ',data,slot,0x400000+textpos,len(value));slot+=16
            data[textpos:textpos+len(value)]=value;textpos+=len(value)
        slot+=16
    return bytes(data)


def bit_reverse(data):return bytes(int(f'{x:08b}'[::-1],2) for x in data)


def go_padding(number):
    value=number*2;encoded=[]
    while value>=128:encoded.append((value&127)|128);value>>=7
    encoded.append(value)
    values=bit_reverse(encoded);n=0
    for i,b in enumerate(values):
        n|=(b&127)<<(i*7)
        if not b&128:break
    return abs(-(n//2)-1 if n&1 else n//2)


def packed(payload=None,*,self_prefix=False,compressed_plaintext=None,numbers=(100000,),header_version=13):
    decoded_launcher=launcher(numbers);off=100000;signature=b'QA!X';carrier=bytearray(elf(548))
    # Synthetic carrier header records, checked before the mocked vendor decode.
    struct.pack_into('<I4sHBB',carrier,120,0,signature,256,header_version,22)
    header=bytearray(32);header[:4]=signature;header[4:6]=bytes([header_version,22])
    struct.pack_into('<I',header,24,len(decoded_launcher));header[31]=sum(header[4:31])%251
    carrier[512:544]=header;prefix=bytes(carrier)+bytes(off-len(carrier))
    payload=prefix if self_prefix else (elf() if payload is None else payload)
    plaintext=zlib.compress(base64.b64encode(payload)) if compressed_plaintext is None else compressed_plaintext
    key=hashlib.new('sha512_256',prefix).digest();nonce=bytes([7])*12
    ciphertext=nonce+AESGCM(key).encrypt(nonce,plaintext,None)
    data=prefix+bit_reverse(ciphertext)[::-1]+bytes(go_padding(off))
    return data,decoded_launcher,payload
