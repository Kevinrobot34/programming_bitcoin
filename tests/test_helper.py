from io import BytesIO

import pytest
import src.helper as target


@pytest.mark.parametrize('b, expected', [
    (b'\x00\x00\x00\x00\x05', '11116'),
    (b'\x05', '6'),
    (b'\x3a', '21'),
    (b'\x39', 'z'),
])
def test_encode_base58(b: bytes, expected: str):
    assert target.encode_base58(b) == expected


@pytest.mark.parametrize('s, expected', [
    ('11116', b'\x00\x00\x00\x00\x05'),
    ('6', b'\x05'),
    ('21', b'\x3a'),
    ('z', b'\x39'),
])
def test_decode_base58(s: str, expected: bytes):
    assert target.decode_base58(s) == expected


@pytest.mark.parametrize(
    'b', [b'\x00\x00\x00\x00\x05', b'\x05', b'\xff', b'\x00\xff'])
def test_encode_decode_base58(b: bytes):
    assert b == target.decode_base58(target.encode_base58(b))


@pytest.mark.parametrize(
    'b', [b'\x00\x00\x00\x00\x05', b'\x05', b'\xff', b'\x00\xff'])
def test_encode_decode_base58_checksum(b: bytes):
    assert b == target.decode_base58_checksum(target.encode_base58_checksum(b))


@pytest.mark.parametrize('s, expected', [
    ('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf',
     '6f507b27411ccf7f16f10297de6cef3f291623eddf'),
])
def test_decode_base58_checksum(s: str, expected: str):
    assert target.decode_base58_checksum(s).hex() == expected


@pytest.mark.parametrize('s', [
    '11116' + 'aaaa',
    '21' + 'bbbb',
])
def test_decode_base58_checksum_fail(s: str):
    with pytest.raises(ValueError):
        target.decode_base58_checksum(s)


@pytest.mark.parametrize('b, expected', [
    (bytes.fromhex('f401'), 500),
    (bytes.fromhex('99c3980000000000'), 10011545),
    (bytes.fromhex('a135ef0100000000'), 32454049),
])
def test_little_endian_to_int(b: bytes, expected: int):
    assert target.little_endian_to_int(b) == expected


@pytest.mark.parametrize('n, length, expected', [
    (500, 2, bytes.fromhex('f401')),
    (10011545, 8, bytes.fromhex('99c3980000000000')),
    (32454049, 8, bytes.fromhex('a135ef0100000000')),
])
def test_int_to_little_endian(n: int, length: int, expected: bytes):
    assert target.int_to_little_endian(n, length) == expected


@pytest.mark.parametrize('b, expected', [
    (b'\x01', 1),
    (b'\xfc', 252),
    (b'\xfd' + b'\xfd\x00', 253),
    (b'\xfd' + b'\xff\x00', 255),
    (b'\xfd' + b'\x2b\x02', 555),
    (b'\xfe' + b'\x00\x00\x01\x00', 1 << 16),
    (b'\xff' + b'\x00\x00\x00\x00\x01\x00\x00\x00', 1 << 32),
])
def test_read_varint(b: bytes, expected: int):
    s = BytesIO(b)
    assert target.read_varint(s) == expected


@pytest.mark.parametrize('i, expected', [
    (1, b'\x01'),
    (252, b'\xfc'),
    (253, b'\xfd' + b'\xfd\x00'),
    (255, b'\xfd' + b'\xff\x00'),
    (555, b'\xfd' + b'\x2b\x02'),
    (1 << 16, b'\xfe' + b'\x00\x00\x01\x00'),
    (1 << 32, b'\xff' + b'\x00\x00\x00\x00\x01\x00\x00\x00'),
])
def test_encode_varint(i: int, expected: bytes):
    assert target.encode_varint(i) == expected


@pytest.mark.parametrize('i', [
    0x1_0000_0000_0000_0000,
    0x1_0000_0000_0000_0000_0000,
])
def test_encode_varint_raise(i: int):
    with pytest.raises(ValueError, match='Integer too large:'):
        target.encode_varint(i)


@pytest.mark.parametrize('h160, testnet, expected', [
    (bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56'), False,
     '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'),
    (bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56'), True,
     'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'),
])
def test_h160_to_p2pkh_address(h160: bytes, testnet: bool, expected: str):
    assert target.h160_to_p2pkh_address(h160, testnet) == expected


@pytest.mark.parametrize('h160, testnet, expected', [
    (bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56'), False,
     '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'),
    (bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56'), True,
     '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'),
])
def test_h160_to_p2sh_address(h160: bytes, testnet: bool, expected: str):
    assert target.h160_to_p2sh_address(h160, testnet) == expected
