from io import BytesIO

import pytest
import src.block as target
from numpy import block


def test_block1():
    block_raw = bytes.fromhex(
        '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
    )
    stream = BytesIO(block_raw)

    # parse
    block = target.Block.parse(stream)
    assert block.version == 0x20000002
    assert block.prev_block == bytes.fromhex(
        '000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e')
    assert block.merkle_root == bytes.fromhex(
        'be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b')
    assert block.timestamp == 0x59a7771e
    assert block.bits == bytes.fromhex('e93c0118')
    assert block.nonce == bytes.fromhex('a4ffd71d')

    # serialize
    assert block.serialize() == block_raw

    # hash
    h = bytes.fromhex(
        '0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523')
    assert block.hash() == h

    # target
    t = 0x13ce9000000000000000000000000000000000000000000
    assert block.target() == t

    # difficulty
    diff = 888171856257
    assert int(block.difficulty()) == diff


@pytest.mark.parametrize('version, expected', [
    (1, False),
    (1 << 29, True),
    (3 << 29, False),
    (1 << 29 | 1, True),
])
def test_bip9(version: int, expected: bool):
    block = target.Block(version,
                         prev_block=b'ff',
                         merkle_root=b'ff',
                         timestamp=1,
                         bits=b'11223344',
                         nonce=b'11223344')
    assert block.bip9() == expected


@pytest.mark.parametrize('version, expected', [
    (1, False),
    (1 << 4, True),
    ((1 << 4) | (1 << 29), True),
])
def test_bip91(version: int, expected: bool):
    block = target.Block(version,
                         prev_block=b'ff',
                         merkle_root=b'ff',
                         timestamp=1,
                         bits=b'11223344',
                         nonce=b'11223344')
    assert block.bip91() == expected


@pytest.mark.parametrize('version, expected', [
    (1, False),
    (1 << 1, True),
    ((1 << 1) | (1 << 29), True),
])
def test_bip141(version: int, expected: bool):
    block = target.Block(version,
                         prev_block=b'ff',
                         merkle_root=b'ff',
                         timestamp=1,
                         bits=b'11223344',
                         nonce=b'11223344')
    assert block.bip141() == expected


@pytest.mark.parametrize('block_hex, expected', [
    ('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1',
     True),
    ('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0',
     False),
])
def test_check_pow(block_hex: str, expected: bool):
    block_raw = bytes.fromhex(block_hex)
    stream = BytesIO(block_raw)
    block = target.Block.parse(stream)
    assert block.check_pow() == expected
