from io import BytesIO

import pytest
import src.script as target


@pytest.mark.parametrize('b, expected', [
    (bytes.fromhex('06' + '767695935687'),
     [0x76, 0x76, 0x95, 0x93, 0x56, 0x87]),
])
def test_script_parse(b: bytes, expected: list):
    s = target.Script.parse(BytesIO(b))
    assert s.cmds == expected


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
