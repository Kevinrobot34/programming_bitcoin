from __future__ import annotations

from io import BytesIO

from src.helper import hash256, int_to_little_endian, little_endian_to_int

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'


class NetworkEnvelope:
    def __init__(self, command: bytes, payload: bytes, testnet: bool = False):
        if len(command) > 12:
            raise ValueError('Command is too long')
        self.command = command
        self.payload = payload
        self.magic: bytes = TESTNET_NETWORK_MAGIC if testnet else NETWORK_MAGIC

    def __repr__(self) -> str:
        return f'{self.command.decode("ascii")}: {self.payload.hex()}'

    @classmethod
    def parse(cls, stream: BytesIO, testnet: bool = False) -> NetworkEnvelope:
        magic = stream.read(4)
        if magic == b'':
            raise IOError('Connection reset!')
        expected_magic = TESTNET_NETWORK_MAGIC if testnet else NETWORK_MAGIC
        if magic != expected_magic:
            raise SyntaxError(
                'Parsing NetworkEnvelope failed: Invalid network magic')
        command = stream.read(12)
        command = command.rstrip(b'\x00')
        payload_length = little_endian_to_int(stream.read(4))
        payload_checksum = stream.read(4)
        payload = stream.read(payload_length)
        if hash256(payload)[:4] != payload_checksum:
            raise IOError('checksum does not match')
        return cls(command, payload, testnet=testnet)

    def serialize(self) -> bytes:
        result = self.magic
        result += self.command + b'\x00' * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload)[:4]
        result += self.payload
        return result
