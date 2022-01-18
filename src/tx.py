from __future__ import annotations

import json
from io import BytesIO
from typing import Optional

import requests

from src.helper import (SIGHASH_ALL, encode_varint, hash256,
                        int_to_little_endian, little_endian_to_int,
                        read_varint)
from src.script import Script, is_p2sh_script_pubkey
from src.secp256k1 import PrivateKey


class Tx:
    bytes_version = 4
    bytes_locktime = 4

    def __init__(self,
                 version: int,
                 tx_ins: list[TxIn],
                 tx_outs: list[TxOut],
                 locktime: int,
                 testnet: bool = False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def id(self) -> str:
        return self.hash().hex()

    def hash(self) -> bytes:
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, stream, testnet: bool = False) -> Tx:
        version = little_endian_to_int(stream.read(cls.bytes_version))

        n_tx_in = read_varint(stream)
        tx_ins = []
        for _ in range(n_tx_in):
            tx_ins.append(TxIn.parse(stream))

        n_tx_out = read_varint(stream)
        tx_outs = []
        for _ in range(n_tx_out):
            tx_outs.append(TxOut.parse(stream))

        locktime = little_endian_to_int(stream.read(cls.bytes_locktime))
        return cls(version, tx_ins, tx_outs, locktime, testnet=testnet)

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.version, self.bytes_version)

        result += encode_varint(len(self.tx_ins))
        for tx_in_i in self.tx_ins:
            result += tx_in_i.serialize()

        result += encode_varint(len(self.tx_outs))
        for tx_out_i in self.tx_outs:
            result += tx_out_i.serialize()

        result += int_to_little_endian(self.locktime, self.bytes_locktime)
        return result

    def fee(self) -> int:
        in_values = 0
        for tx_in_i in self.tx_ins:
            in_values += tx_in_i.value()
        out_amounts = 0
        for tx_out_i in self.tx_outs:
            out_amounts += tx_out_i.amount
        return in_values - out_amounts

    def sig_hash(self,
                 input_index: int,
                 hash_type: int = SIGHASH_ALL,
                 redeem_script: Optional[Script] = None) -> int:
        modified_tx_ins = [
            TxIn(prev_tx=tx_in.prev_tx,
                 prev_index=tx_in.prev_index,
                 script_sig=redeem_script
                 if redeem_script else tx_in.script_pubkey(self.testnet),
                 sequence=tx_in.sequence)
            if i == input_index else TxIn(prev_tx=tx_in.prev_tx,
                                          prev_index=tx_in.prev_index,
                                          script_sig=None,
                                          sequence=tx_in.sequence)
            for i, tx_in in enumerate(self.tx_ins)
        ]
        modified_tx = Tx(version=self.version,
                         tx_ins=modified_tx_ins,
                         tx_outs=self.tx_outs,
                         locktime=self.locktime)

        h256 = hash256(modified_tx.serialize() +
                       int_to_little_endian(hash_type, 4))
        return int.from_bytes(h256, 'big')

    def verify_input(self, input_index: int) -> bool:
        # verify i-th transaction input
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        if is_p2sh_script_pubkey(script_pubkey.cmds):
            cmd = tx_in.script_sig.cmds[-1]
            if isinstance(cmd, bytes):
                raw_redeem = encode_varint(len(cmd)) + cmd
                redeem_script = Script.parse(BytesIO(raw_redeem))
            else:
                raise ValueError('Invalid type: RedeemScript in ScriptSig')
        else:
            redeem_script = None
        script_sig = tx_in.script_sig
        z = self.sig_hash(input_index, redeem_script=redeem_script)
        s = script_sig + script_pubkey
        return s.evaluate(z)

    def verify(self) -> bool:
        # verify whole transaction
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_input(self,
                   pk: PrivateKey,
                   input_index: int,
                   hash_type: int = SIGHASH_ALL) -> bool:
        z = self.sig_hash(input_index, hash_type)
        der = pk.sign(z).der()
        sig = der + hash_type.to_bytes(1, 'big')
        sec = pk.public_point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        return self.verify_input(input_index)


class TxIn:
    def __init__(self,
                 prev_tx: bytes,
                 prev_index: int,
                 script_sig: Optional[Script] = None,
                 sequence: int = 0xff_ff_ff_ff) -> None:
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self) -> str:
        return f'{self.prev_tx.hex()}:{self.prev_index}'

    @classmethod
    def parse(cls, stream: BytesIO) -> TxIn:
        prev_tx = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet: bool = False) -> Tx:
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet: bool = False) -> int:
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet: bool = False) -> Script:
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pub_key


class TxOut:
    def __init__(self, amount: int, script_pub_key: Script) -> None:
        self.amount = amount
        self.script_pub_key = script_pub_key

    def __repr__(self) -> str:
        return f'{self.amount}:{self.script_pub_key}'

    @classmethod
    def parse(cls, stream: BytesIO) -> TxOut:
        amount = little_endian_to_int(stream.read(8))
        script_pub_key = Script.parse(stream)
        return cls(amount, script_pub_key)

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pub_key.serialize()
        return result


class TxFetcher:
    cache: dict[str, Tx] = {}

    @classmethod
    def get_url(cls, testnet: bool = False) -> str:
        # https://blockstream.info/nojs/
        # https://github.com/Blockstream/esplora/blob/master/API.md
        if testnet:
            return 'https://blockstream.info/testnet/api'
        else:
            return 'https://blockstream.info/api'

    @classmethod
    def fetch(cls,
              tx_id: str,
              testnet: bool = False,
              fresh: bool = False) -> Tx:
        if fresh or (tx_id not in cls.cache):
            url = f'{cls.get_url(testnet)}/tx/{tx_id}/hex'
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(f'unexpected response: {response.text}')
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)

            if tx.id() != tx_id:
                raise ValueError(f'not the same id {tx.id()} vs {tx_id}.')

            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename: str):
        with open(filename, 'r') as reader:
            disk_cache = json.loads(reader.read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename: str):
        with open(filename, 'w') as writer:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            writer.write(s)
