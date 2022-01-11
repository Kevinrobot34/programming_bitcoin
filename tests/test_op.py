import pytest
import src.op as target


@pytest.mark.parametrize('n, expected', [
    (0, b''),
    (1, b'\x01'),
    (-1, b'\x81'),
    (255, b'\xff\x00'),
    (-255, b'\xff\x80'),
    (256, b'\x00\x01'),
    (-256, b'\x00\x81'),
])
def test_encode_num(n: int, expected: bytes):
    assert target.encode_num(n) == expected


@pytest.mark.parametrize('b, expected', [
    (b'', 0),
    (b'\x01', 1),
    (b'\x81', -1),
    (b'\xff\x00', 255),
    (b'\xff\x80', -255),
    (b'\x00\x01', 256),
    (b'\x00\x81', -256),
])
def test_decode_num(b: bytes, expected: int):
    assert target.decode_num(b) == expected
