import pytest
import src.op as target
from src.helper import int_to_little_endian
from src.secp256k1 import PrivateKey


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
    assert target.op_0(s)
    assert s == [6, 5, 4, 3, 2, 1, b'']

    s = stack[:]
    assert target.op_nop(s)
    assert s == [6, 5, 4, 3, 2, 1]

    s = stack[:]
    assert not target.op_return(s)
    assert s == [6, 5, 4, 3, 2, 1]

    s = stack[:]
    assert target.op_1negate(s)
    assert s == [6, 5, 4, 3, 2, 1, b'\x81']

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
    assert target.op_nip(s)  # 119
    assert s == [6, 5, 4, 3, 1]

    s = stack[:]
    assert target.op_over(s)  # 120
    assert s == [6, 5, 4, 3, 2, 1, 2]

    s = stack[:]
    assert target.op_rot(s)  # 123
    assert s == [6, 5, 4, 2, 1, 3]

    s = stack[:]
    assert target.op_tuck(s)  # 125
    assert s == [6, 5, 4, 3, 1, 2, 1]


def test_operations2():
    stack = [b'\x5a', b'\x5b', b'\x5c', b'\x5d']

    s = stack[:]
    assert target.op_size(s)  # 130
    assert s == [b'\x5a', b'\x5b', b'\x5c', b'\x5d', b'\x01']

    s = stack[:]
    assert target.op_1add(s)  # 139
    assert s == [b'\x5a', b'\x5b', b'\x5c', b'\x5e']

    s = stack[:]
    assert target.op_1sub(s)  # 140
    assert s == [b'\x5a', b'\x5b', b'\x5c', b'\x5c']

    s = stack[:]
    assert target.op_negate(s)  # 143
    assert s == [b'\x5a', b'\x5b', b'\x5c', b'\xdd']

    s = stack[:]
    assert target.op_add(s)  # 147
    assert s == [b'\x5a', b'\x5b', b'\xb9\x00']

    s = stack[:]
    assert target.op_sub(s)  # 148
    assert s == [b'\x5a', b'\x5b', b'\x81']

    s = stack[:]
    assert target.op_mul(s)  # 149
    assert s == [b'\x5a', b'\x5b', b'\x6c\x21']


def test_operations3():
    stack = [4, 3, 2, 1, target.encode_num(3)]

    s = stack[:]
    assert target.op_pick(s)  # 121
    assert s == [4, 3, 2, 1, 4]

    s = stack[:]
    assert target.op_roll(s)  # 122
    assert s == [3, 2, 1, 4]


@pytest.mark.parametrize('s, expected_s, expected_r', [
    ([], [], False),
    ([b''], [], False),
    ([b'\x01'], [], True),
    ([b'\xff'], [], True),
    ([b'\x01', b'\x02'], [b'\x01'], True),
])
def test_op_verify(s: list, expected_s: list, expected_r: bool):
    ret = target.op_verify(s)  # 105
    assert s == expected_s
    assert ret == expected_r


@pytest.mark.parametrize('s, expected_s, expected_r', [
    ([], [], False),
    ([b''], [b''], True),
    ([b'\x01'], [b'\x01', b'\x01'], True),
    ([b'\x01', b'\x02'], [b'\x01', b'\x02', b'\x02'], True),
])
def test_op_ifdup(s: list, expected_s: list, expected_r: bool):
    ret = target.op_ifdup(s)  # 115
    assert s == expected_s
    assert ret == expected_r


@pytest.mark.parametrize('s, expected', [
    ([b'\x01'], [b'\x01']),
    ([b'\x81'], [b'\x01']),
])
def test_op_abs(s: list, expected: list):
    assert target.op_abs(s)  # 144
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b''], [b'\x01']),
    ([b'\x01'], [b'']),
    ([b'\x02'], [b'']),
])
def test_op_not(s: list, expected: list):
    assert target.op_not(s)  # 145
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b''], [b'']),
    ([b'\x01'], [b'\x01']),
    ([b'\x02'], [b'\x01']),
])
def test_op_0notequal(s: list, expected: list):
    assert target.op_0notequal(s)  # 146
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'']),
    ([b'', b'\x01'], [b'']),
    ([b'', b''], [b'']),
])
def test_op_booland(s: list, expected: list):
    assert target.op_booland(s)  # 154
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'\x01']),
    ([b'', b'\x01'], [b'\x01']),
    ([b'', b''], [b'']),
])
def test_op_boolor(s: list, expected: list):
    assert target.op_boolor(s)  # 155
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'']),
    ([b'', b'\x01'], [b'']),
    ([b'', b''], [b'\x01']),
])
def test_op_numequal(s: list, expected: list):
    assert target.op_numequal(s)  # 156
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'']),
    ([b'\x01', b''], [b'\x01']),
    ([b'', b'\x01'], [b'\x01']),
    ([b'', b''], [b'']),
])
def test_op_numnotequal(s: list, expected: list):
    assert target.op_numnotequal(s)  # 158
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'']),
    ([b'\x01', b''], [b'']),
    ([b'', b'\x01'], [b'\x01']),
    ([b'', b''], [b'']),
])
def test_op_lessthan(s: list, expected: list):
    assert target.op_lessthan(s)  # 159
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'']),
    ([b'\x01', b''], [b'\x01']),
    ([b'', b'\x01'], [b'']),
    ([b'', b''], [b'']),
])
def test_op_greaterthan(s: list, expected: list):
    assert target.op_greaterthan(s)  # 160
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'']),
    ([b'', b'\x01'], [b'\x01']),
    ([b'', b''], [b'\x01']),
])
def test_op_lessthanorequal(s: list, expected: list):
    assert target.op_lessthanorequal(s)  # 161
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'\x01']),
    ([b'', b'\x01'], [b'']),
    ([b'', b''], [b'\x01']),
])
def test_op_greaterthanorequal(s: list, expected: list):
    assert target.op_greaterthanorequal(s)  # 162
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'']),
    ([b'', b'\x01'], [b'']),
    ([b'', b''], [b'']),
])
def test_op_min(s: list, expected: list):
    assert target.op_min(s)  # 163
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x01'], [b'\x01']),
    ([b'\x01', b''], [b'\x01']),
    ([b'', b'\x01'], [b'\x01']),
    ([b'', b''], [b'']),
])
def test_op_max(s: list, expected: list):
    assert target.op_max(s)  # 164
    assert s == expected


@pytest.mark.parametrize('s, expected', [
    ([b'\x01', b'\x03', b'\x07'], [b'']),
    ([b'\x04', b'\x03', b'\x07'], [b'\x01']),
    ([b'\x09', b'\x03', b'\x07'], [b'']),
])
def test_op_within(s: list, expected: list):
    assert target.op_within(s)  # 165
    assert s == expected


def test_op_checksig_1():
    z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
    sec = bytes.fromhex(
        '04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34'
    )
    sig = bytes.fromhex(
        '3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601'
    )
    stack = [sig, sec]
    assert target.op_checksig(stack, z)
    assert target.decode_num(stack[0]) == 1


def test_op_checksig_2():
    z = 456
    pk = PrivateKey(secret=123)
    sig = pk.sign(z).der() + int_to_little_endian(1, 1)
    sec = pk.public_point.sec()
    stack = [sig, sec]
    assert target.op_checksig(stack, z)
    assert target.decode_num(stack[0]) == 1

    stack = [sig, sec]
    assert target.op_checksig(stack, z + 1)
    assert target.decode_num(stack[0]) == 0


def test_op_checksig_fail_1():
    z = 456
    pk = PrivateKey(secret=123)
    sig_true = pk.sign(z).der() + int_to_little_endian(1, 1)
    sig_false = pk.sign(z).der() + int_to_little_endian(1, 5)
    sec_true = pk.public_point.sec()
    sec_false = int_to_little_endian(1, 5) + pk.public_point.sec()

    stack = [sig_false, sec_true]
    assert not target.op_checksig(stack, z)

    stack = [sig_true, sec_false]
    assert not target.op_checksig(stack, z)


def test_op_checkmultisig_1():
    # 2-of-2 bare multisig
    z = 456
    pk1 = PrivateKey(secret=123)
    sig1 = pk1.sign(z).der() + int_to_little_endian(1, 1)
    sec1 = pk1.public_point.sec()

    pk2 = PrivateKey(secret=789)
    sig2 = pk2.sign(z).der() + int_to_little_endian(1, 1)
    sec2 = pk2.public_point.sec()

    stack = [b'', sig1, sig2, b'\x02', sec1, sec2, b'\x02']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1


def test_op_checkmultisig_2():
    # 1-of-2 bare multisig
    z = 456
    pk1 = PrivateKey(secret=123)
    sig1 = pk1.sign(z).der() + int_to_little_endian(1, 1)
    sec1 = pk1.public_point.sec()

    pk2 = PrivateKey(secret=789)
    sig2 = pk2.sign(z).der() + int_to_little_endian(1, 1)
    sec2 = pk2.public_point.sec()

    stack = [b'', sig2, b'\x01', sec1, sec2, b'\x02']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1

    stack = [b'', sig1, b'\x01', sec1, sec2, b'\x02']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1


def test_op_checkmultisig_3():
    # 2-of-3 bare multisig
    z = 456
    pk1 = PrivateKey(secret=123)
    sig1 = pk1.sign(z).der() + int_to_little_endian(1, 1)
    sec1 = pk1.public_point.sec()

    pk2 = PrivateKey(secret=789)
    sig2 = pk2.sign(z).der() + int_to_little_endian(1, 1)
    sec2 = pk2.public_point.sec()

    pk3 = PrivateKey(secret=555)
    sig3 = pk3.sign(z).der() + int_to_little_endian(1, 1)
    sec3 = pk3.public_point.sec()

    stack = [b'', sig2, b'\x01', sec1, sec2, sec3, b'\x03']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1

    stack = [b'', sig1, sig3, b'\x02', sec1, sec2, sec3, b'\x03']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1

    stack = [b'', sig2, sig3, b'\x02', sec1, sec2, sec3, b'\x03']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1

    stack = [b'', sig1, sig2, sig3, b'\x03', sec1, sec2, sec3, b'\x03']
    assert target.op_checkmultisig(stack, z)
    assert target.decode_num(stack[0]) == 1

    # fail!!
    stack = [b'', sig3, sig1, b'\x02', sec1, sec2, sec3, b'\x03']
    assert not target.op_checkmultisig(stack, z)
