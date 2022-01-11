from io import BytesIO

import pytest
import src.script as target
from src.op import encode_num


@pytest.mark.parametrize('b, expected', [
    (bytes.fromhex('06' + '767695935687'),
     [0x76, 0x76, 0x95, 0x93, 0x56, 0x87]),
    (b'\x04' + b'\x03' + b'\xff\xee\xdd', [b'\xff\xee\xdd']),
    (b'\x52' + b'\x4c' + b'\x50' + b'\xff' * 80, [b'\xff' * 80]),
    (b'\xfd\x07\x01' + b'\x4d' + b'\x04\x01' + b'\xff' * 260, [b'\xff' * 260]),
])
def test_script_parse(b: bytes, expected: list):
    s = target.Script.parse(BytesIO(b))
    assert s.cmds == expected


@pytest.mark.parametrize('cmds, expected', [
    ([b'\xff\xee\xdd'], b'\x04' + b'\x03' + b'\xff\xee\xdd'),
    ([b'\xff' * 80], b'\x52' + b'\x4c' + b'\x50' + b'\xff' * 80),
    ([b'\xff' * 260], b'\xfd\x07\x01' + b'\x4d' + b'\x04\x01' + b'\xff' * 260),
])
def test_script_serialize(cmds: list, expected: bytes):
    s = target.Script(cmds=cmds)
    assert s.serialize() == expected


def test_script_serialize_raise():
    s = target.Script(cmds=[b'\xff' * 521])
    with pytest.raises(ValueError):
        s.raw_serialize()


def test_script_evaluate1():
    # OP_5, OP_ADD, OP_9, OP_EQUAL
    script_pub_key = target.Script([85, 147, 89, 135])
    # OP_4
    script_sig = target.Script([84])

    s = script_sig + script_pub_key
    assert s.evaluate(0)


def test_script_evaluate2():
    # OP_DUP, OP_DUP, OP_MUL, OP_ADD, OP_6, OP_EQUAL
    script_pub_key = target.Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])
    # OP_2
    script_sig = target.Script([82])

    s = script_sig + script_pub_key
    assert s.evaluate(0)


def test_script_evaluate3():
    # OP_ADD, ..., OP_ADD, OP_6, OP_EQUAL
    cmds = [0x93] * 15 + [encode_num(136), 0x87]
    script_pub_key = target.Script(cmds)
    # OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16
    script_sig = target.Script(
        [81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96])

    s = script_sig + script_pub_key
    assert s.evaluate(0)
