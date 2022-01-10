import hashlib
from io import BytesIO

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def hash160(s: bytes) -> bytes:
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s: bytes) -> bytes:
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(b: bytes) -> str:
    count = 0
    for bi in b:
        if bi == 0:
            count += 1
        else:
            break
    num = int.from_bytes(b, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def decode_base58(s: str) -> bytes:
    ret = 0
    for si in s:
        ret *= 58
        ret += BASE58_ALPHABET.index(si)
    n_prefix_1 = len(s) - len(s.lstrip('1'))
    n = n_prefix_1 + (ret + 256 - 1) // 256
    return ret.to_bytes(n, 'big')


def encode_base58_checksum(b: bytes) -> str:
    return encode_base58(b + hash256(b)[:4])


def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')


def read_varint(s: BytesIO):
    i = s.read(1)[0]
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i


def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return bytes([i])
    elif i < 0x1_0000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x1_0000_0000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x1_0000_0000_0000_0000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError(f'Integer too large: {i}.')
