import hashlib
from io import BytesIO

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
MAX_TARGET = 0xffff * 256**(0x1d - 3)
TWOWEEKS = 14 * 24 * 60 * 60


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
    n = 0
    r = ret
    while r > 0:
        n += 1
        r //= 256
    return ret.to_bytes(n_prefix_1 + n, 'big')


def encode_base58_checksum(b: bytes) -> str:
    return encode_base58(b + hash256(b)[:4])


def decode_base58_checksum(s: str) -> bytes:
    b_cs = decode_base58(s)
    b = b_cs[:-4]
    checksum = b_cs[-4:]
    if hash256(b)[:4] != checksum:
        raise ValueError('Invalid checksum')
    return b


def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')


def read_varint(s: BytesIO) -> int:
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


def h160_to_p2pkh_address(h160: bytes, testnet: bool = False) -> str:
    prefix = b'\x6f' if testnet else b'\x00'
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160: bytes, testnet=False) -> str:
    prefix = b'\xc4' if testnet else b'\x05'
    return encode_base58_checksum(prefix + h160)


def bits_to_target(bits: bytes) -> int:
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    target = coefficient * (256**(exponent - 3))
    return target


def target_to_bits(target: int) -> bytes:
    raw_bytes = target.to_bytes(32, 'big')
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    bits = coefficient[::-1] + bytes([exponent])
    return bits


def calculate_new_bits(previous_bits: bytes, time_diff: int) -> bytes:
    if time_diff > TWOWEEKS * 4:
        time_diff = TWOWEEKS * 4
    if time_diff < TWOWEEKS // 4:
        time_diff = TWOWEEKS // 4
    new_target = bits_to_target(previous_bits) * time_diff // TWOWEEKS
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    return target_to_bits(new_target)
