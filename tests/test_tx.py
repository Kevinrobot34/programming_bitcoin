from io import BytesIO
from typing import Optional

import pytest
import src.tx as target
from src.script import Script
from src.secp256k1 import PrivateKey


@pytest.mark.parametrize('a, s', [
    (1, Script([b'\xff\xee\xdd'])),
    (0xffff, Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])),
])
def test_txout_serialize_parse(a: int, s: Script):
    t = target.TxOut(amount=a, script_pub_key=s)
    t_restored = target.TxOut.parse(BytesIO(t.serialize()))
    assert t.amount == t_restored.amount
    assert t.script_pub_key.cmds == t_restored.script_pub_key.cmds


@pytest.mark.parametrize('prev_tx, prev_index, script_sig, sequence', [
    (bytes.fromhex(
        'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'), 0,
     Script.parse(
         BytesIO(
             bytes.fromhex(
                 '6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
             ))), 0xfffffffe),
    (bytes.fromhex(
        'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'), 0,
     None, 0xfffffffe),
])
def test_txin_serialize_parse(prev_tx: bytes, prev_index: int,
                              script_sig: Optional[Script], sequence: int):
    t = target.TxIn(prev_tx, prev_index, script_sig, sequence)
    t_restored = target.TxIn.parse(BytesIO(t.serialize()))
    assert t.prev_tx == t_restored.prev_tx
    assert t.prev_index == t_restored.prev_index
    assert t.script_sig.cmds == t_restored.script_sig.cmds
    assert t.sequence == t_restored.sequence


def test_tx_parse1():
    hex_str = '0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600'
    stream = BytesIO(bytes.fromhex(hex_str))
    tx = target.Tx.parse(stream)

    assert tx.version == 1
    assert tx.locktime == 410393
    assert tx.fee() == 40000

    # TxIn
    assert len(tx.tx_ins) == 1
    assert tx.tx_ins[0].prev_tx == bytes.fromhex(
        'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
    assert tx.tx_ins[0].prev_index == 0
    assert tx.tx_ins[0].script_sig.serialize() == bytes.fromhex(
        '6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
    )
    assert tx.tx_ins[0].sequence == 0xfffffffe

    # TxOut
    assert len(tx.tx_outs) == 2
    assert tx.tx_outs[0].amount == 32454049
    assert tx.tx_outs[0].script_pub_key.serialize() == bytes.fromhex(
        '1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
    assert tx.tx_outs[1].amount == 10011545
    assert tx.tx_outs[1].script_pub_key.serialize() == bytes.fromhex(
        '1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac')


@pytest.mark.parametrize('hex_str, expected', [
    ('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600',
     40000),
    ('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600',
     140500)
])
def test_tx_fee(hex_str: str, expected: int):
    stream = BytesIO(bytes.fromhex(hex_str))
    tx = target.Tx.parse(stream)
    assert tx.fee() == expected


@pytest.mark.parametrize('tx_id, input_index, expected', [
    ('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03', 0,
     int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6',
         16)),
])
def test_tx_sig_hash(tx_id: str, input_index: int, expected: int):
    tx = target.TxFetcher.fetch(tx_id)
    assert tx.sig_hash(input_index) == expected


@pytest.mark.parametrize('tx_id, testnet', [
    ('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03',
     False),
])
def test_tx_verify_p2pkh(tx_id: str, testnet: bool):
    tx = target.TxFetcher.fetch(tx_id=tx_id, testnet=testnet)
    assert tx.verify()


def test_script_p2sh_1():
    tx = target.TxFetcher.fetch(
        '46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b')
    assert tx.verify()


def test_tx_sign_input():
    private_key = PrivateKey(secret=8675309)
    stream = BytesIO(
        bytes.fromhex(
            '010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000'
        ))
    tx = target.Tx.parse(stream, testnet=True)
    assert tx.sign_input(pk=private_key, input_index=0)
    want = '010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d0000006b4830450221008ed46aa2cf12d6d81065bfabe903670165b538f65ee9a3385e6327d80c66d3b502203124f804410527497329ec4715e18558082d489b218677bd029e7fa306a72236012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000'
    assert tx.serialize().hex() == want


def test_tx_is_coinbase():
    raw_tx = bytes.fromhex(
        '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000'
    )
    stream = BytesIO(raw_tx)
    tx = target.Tx.parse(stream)
    assert tx.is_coinbase()


def test_tx_coinbase_height():
    raw_tx1 = bytes.fromhex(
        '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000'
    )
    stream1 = BytesIO(raw_tx1)
    tx1 = target.Tx.parse(stream1)
    assert tx1.coinbase_height() == 465879

    raw_tx2 = bytes.fromhex(
        '0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600'
    )
    stream2 = BytesIO(raw_tx2)
    tx2 = target.Tx.parse(stream2)
    assert tx2.coinbase_height() is None
