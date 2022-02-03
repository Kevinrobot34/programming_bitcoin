from __future__ import annotations

import time
from io import BytesIO
from random import randint
from typing import Optional

from src.helper import (encode_varint, hash256, int_to_little_endian,
                        little_endian_to_int)

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


class VersionMessage:
    command = b'version'

    def __init__(self,
                 version: int = 70015,
                 services: int = 0,
                 timestamp: Optional[int] = None,
                 receiver_services: int = 0,
                 receiver_ip: bytes = b'\x00\x00\x00\x00',
                 receiver_port: int = 8333,
                 sender_services: int = 0,
                 sender_ip: bytes = b'\x00\x00\x00\x00',
                 sender_port: int = 8333,
                 nonce: Optional[bytes] = None,
                 user_agent: bytes = b'/programmingbitcoin:0.1/',
                 latest_block: int = 0,
                 relay: bool = False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)

        # receiver info
        result += int_to_little_endian(self.receiver_services, 8)
        result += b'\x00' * 10 + b'\xff' * 2 + self.receiver_ip  # IPv4
        result += int_to_little_endian(self.receiver_port, 2)

        # sender info
        result += int_to_little_endian(self.sender_services, 8)
        result += b'\x00' * 10 + b'\xff' * 2 + self.sender_ip  # IPv4
        result += int_to_little_endian(self.sender_port, 2)

        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        result += int_to_little_endian(self.latest_block, 4)
        result += b'\x01' if self.relay else b'\x00'
        return result
