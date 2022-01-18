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


def test_script_parse_fail1():
    b = b'\x02' + b'\x03' + b'\xff\xee\xdd'
    with pytest.raises(SyntaxError):
        _ = target.Script.parse(BytesIO(b))


@pytest.mark.parametrize('cmds, expected', [
    ([0x76, 0x76, 0x95, 0x93, 0x56, 0x87
      ], bytes.fromhex('06' + '767695935687')),
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


def test_script_evaluate4():
    # OP_2DUP, OP_EQUAL, OP_NOT, OP_VERIFY, OP_SHA1, OP_SWAP, OP_SHA1, OP_EQUAL
    script_pubkey = target.Script(
        [0x6e, 0x87, 0x91, 0x69, 0xa7, 0x7c, 0xa7, 0x87])
    c1 = '255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f576964746820\
32203020522f4865696768742033203020522f547970652034203020522f537562747970652035\
203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e67\
74682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8\
fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1ff\
fe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db169\
0901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc\
942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a215664613097\
89606bd0bf3f98cda8044629a1'

    c2 = '255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f576964746820\
32203020522f4865696768742033203020522f547970652034203020522f537562747970652035\
203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e67\
74682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8\
fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1ff\
fe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a9\
0901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0\
a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd3097\
91d06bd0af3f98cda4bc4629b1'

    collision1 = bytes.fromhex(c1)
    collision2 = bytes.fromhex(c2)
    script_sig = target.Script([collision1, collision2])

    combined_script = script_sig + script_pubkey
    assert combined_script.evaluate(0)


def test_script_evaluate5():
    # OP_5, OP_5, OP_TOALTSTACK, OP_FROMALTSTACK, OP_EQUAL
    s = target.Script([85, 85, 107, 108, 135])
    assert s.evaluate(0)


def test_script_evaluate_fail1():
    # OP_0 -> fail with invalid top element of stack
    s = target.Script([0])
    assert not s.evaluate(0)


def test_script_evaluate_fail2():
    opcodes = [
        107, 108, 109, 110, 111, 112, 113, 114, 115, 117, 118, 119, 120, 121,
        122, 123, 124, 125, 130, 135, 139, 140, 143, 144, 145, 146, 147, 148,
        149, 154, 155, 156, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
        168, 169, 170, 172, 174
    ]
    for opcode in opcodes:
        s = target.Script([opcode])
        assert not s.evaluate(0)


def test_script_evaluate_fail3():
    # OP_NOP -> fail with empty stack
    s = target.Script([97])
    assert not s.evaluate(0)


@pytest.mark.parametrize('cmds, expected', [
    ([0x76, 0xa9, b'11112222333344445555', 0x88, 0xac], True),
    ([0x76, 0xa9, b'11112222333344445555', 0x88], False),
    ([0x76, 0xa9, b'1111', 0x88, 0xac], False),
])
def test_is_p2pkh_script_pubkey(cmds: list, expected: bool):
    assert target.is_p2pkh_script_pubkey(cmds) == expected


@pytest.mark.parametrize('cmds, expected', [
    ([0xa9, b'11112222333344445555', 0x87], True),
    ([0xa9, b'11112222333344445555'], False),
    ([0xa9, b'1111', 0x87], False),
])
def test_is_p2sh_script_pubkey(cmds: list, expected: bool):
    assert target.is_p2sh_script_pubkey(cmds) == expected
