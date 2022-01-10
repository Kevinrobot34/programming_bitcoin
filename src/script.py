from __future__ import annotations

from io import BytesIO
from logging import getLogger
from typing import Optional, Union

from src.helper import (encode_varint, int_to_little_endian,
                        little_endian_to_int, read_varint)
from src.op import (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG,
                    OP_CHECKSIGVERIFY, OP_CODE_FUNCTIONS, OP_CODE_NAMES,
                    OP_FROMALTSTACK, OP_IF, OP_NOTIF, OP_PUSHDATA1,
                    OP_PUSHDATA2, OP_TOALTSTACK)

LOGGER = getLogger(__name__)


class Script:
    def __init__(self, cmds: Optional[list[Union[bytes, int]]] = None) -> None:
        self.cmds: list[Union[bytes, int]] = cmds if cmds is not None else []

    def __add__(self, other: Script) -> Script:
        return self.__class__(self.cmds + other.cmds)

    @classmethod
    def parse(cls, stream: BytesIO):
        length = read_varint(stream)
        cmds: list[Union[bytes, int]] = []
        count = 0
        while count < length:
            current: bytes = stream.read(1)
            count += 1
            current_byte: int = current[0]
            if 1 <= current_byte <= 75:
                n = current_byte
                cmds.append(stream.read(n))
                count += n
            elif current_byte == OP_PUSHDATA1:
                data_length = little_endian_to_int(stream.read(1))
                cmds.append(stream.read(data_length))
                count += 1 + data_length
            elif current_byte == OP_PUSHDATA2:
                data_length = little_endian_to_int(stream.read(2))
                cmds.append(stream.read(data_length))
                count += 1 + data_length
            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self) -> bytes:
        result = b''
        for cmd_i in self.cmds:
            if isinstance(cmd_i, int):
                result += int_to_little_endian(cmd_i, 1)
            else:
                length = len(cmd_i)
                if length <= 75:
                    result += int_to_little_endian(length, 1)
                elif length <= 255:
                    result += int_to_little_endian(OP_PUSHDATA1, 1)
                    result += int_to_little_endian(length, 1)
                elif length <= 520:
                    result += int_to_little_endian(OP_PUSHDATA2, 1)
                    result += int_to_little_endian(length, 1)
                else:
                    raise ValueError('too long an cmd')

                result += cmd_i
        return result

    def serialize(self) -> bytes:
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z) -> bool:
        cmds: list[Union[bytes, int]] = self.cmds[:]
        stack: list = []
        altstack: list = []
        while len(cmds) > 0:
            cmd_i = cmds.pop(0)
            if isinstance(cmd_i, int):
                operation = OP_CODE_FUNCTIONS[cmd_i]
                operation_name = OP_CODE_NAMES[cmd_i]
                if cmd_i in (OP_IF, OP_NOTIF):
                    if not operation(stack, cmds):
                        LOGGER.info(f'bad op: {operation_name}')
                        return False
                elif cmd_i in (OP_TOALTSTACK, OP_FROMALTSTACK):
                    if not operation(stack, altstack):
                        LOGGER.info(f'bad op: {operation_name}')
                        return False
                elif cmd_i in (OP_CHECKSIG, OP_CHECKSIGVERIFY,
                               OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                    if not operation(stack, z):
                        LOGGER.info(f'bad op: {operation_name}')
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info(f'bad op: {operation_name}')
                        return False
            else:
                stack.append(cmd_i)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True
