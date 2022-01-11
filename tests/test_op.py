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


def test_operations1():
    stack = [6, 5, 4, 3, 2, 1]

    s = stack[:]
    assert target.op_2drop(s)  # 109
    assert s == [6, 5, 4, 3]

    s = stack[:]
    assert target.op_2dup(s)  # 110
    assert s == [6, 5, 4, 3, 2, 1, 2, 1]

    s = stack[:]
    assert target.op_3dup(s)  # 111
    assert s == [6, 5, 4, 3, 2, 1, 3, 2, 1]

    s = stack[:]
    assert target.op_2over(s)  # 112
    assert s == [6, 5, 4, 3, 2, 1, 4, 3]

    s = stack[:]
    assert target.op_2rot(s)  # 113
    assert s == [4, 3, 2, 1, 6, 5]

    s = stack[:]
    assert target.op_2swap(s)  # 114
    assert s == [6, 5, 2, 1, 4, 3]

    s = stack[:]
    assert target.op_depth(s)  # 116
    assert s == [6, 5, 4, 3, 2, 1, target.encode_num(6)]

    s = stack[:]
    assert target.op_drop(s)  # 117
    assert s == [6, 5, 4, 3, 2]

    s = stack[:]
    assert target.op_over(s)  # 120
    assert s == [6, 5, 4, 3, 2, 1, 2]

    s = stack[:]
    assert target.op_rot(s)  # 123
    assert s == [6, 5, 4, 2, 1, 3]

    s = stack[:]
    assert target.op_tuck(s)  # 125
    assert s == [6, 5, 4, 3, 1, 2, 1]
