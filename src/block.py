from __future__ import annotations

import json
from io import BytesIO

from src.helper import hash256, int_to_little_endian, little_endian_to_int


class Block:
    def __init__(self, version: int, prev_block: bytes, merkle_root: bytes,
                 timestamp: int, bits: bytes, nonce: bytes):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    @classmethod
    def parse(cls, stream: BytesIO) -> Block:
        version = little_endian_to_int(stream.read(4))
        prev_block = stream.read(32)[::-1]
        merkle_root = stream.read(32)[::-1]
        timestamp = little_endian_to_int(stream.read(4))
        bits = stream.read(4)
        nonce = stream.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result = int_to_little_endian(self.timestamp, 4)
        result = self.bits
        result = self.nonce
        return result

    def hash(self) -> bytes:
        return hash256(self.serialize())[::-1]

    def bip9(self) -> bool:
        return self.version >> 29 == 0b001

    def bip91(self) -> bool:
        return (self.version >> 4) & 1 == 1

    def bip141(self) -> bool:
        return (self.version >> 1) & 1 == 1
