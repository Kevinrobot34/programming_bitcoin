import pytest
import src.helper as target


@pytest.mark.parametrize('b, expected', [
    (b'\x00\x00\x00\x00\x05', '11116'),
    (b'\x05', '6'),
])
def test_encode_base58(b: bytes, expected: str):
    assert target.encode_base58(b) == expected


@pytest.mark.parametrize('s, expected', [
    ('11116', b'\x00\x00\x00\x00\x05'),
    ('6', b'\x05'),
])
def test_decode_base58(s: str, expected: bytes):
    assert target.decode_base58(s) == expected


@pytest.mark.parametrize('b', [(b'\x00\x00\x00\x00\x05'), (b'\x05'), (b'\xff'),
                               (b'\x00\xff')])
def test_encode_decode_base58(b: bytes):
    assert b == target.decode_base58(target.encode_base58(b))


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
