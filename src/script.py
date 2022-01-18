from __future__ import annotations

from io import BytesIO
from logging import getLogger
from typing import Optional, Union

from src.helper import (encode_varint, int_to_little_endian,
                        little_endian_to_int, read_varint)
from src.op import (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG,
                    OP_CHECKSIGVERIFY, OP_CODE_FUNCTIONS, OP_CODE_NAMES,
                    OP_FROMALTSTACK, OP_IF, OP_NOTIF, OP_PUSHDATA1,
                    OP_PUSHDATA2, OP_TOALTSTACK, op_equal, op_hash160,
                    op_verify)

LOGGER = getLogger(__name__)


class Script:
    def __init__(self, cmds: Optional[list[Union[bytes, int]]] = None) -> None:
        self.cmds: list[Union[bytes, int]] = cmds if cmds is not None else []

    def __add__(self, other: Script) -> Script:
        return self.__class__(self.cmds + other.cmds)

    def __repr__(self) -> str:
        result: list[str] = []
        for cmd_i in self.cmds:
            if isinstance(cmd_i, int):
                if cmd_i in OP_CODE_NAMES:
                    name = OP_CODE_NAMES[cmd_i]
                else:
                    name = f'OP_[{cmd_i}]'
                result.append(name)
            else:
                result.append(cmd_i.hex())
        return ' '.join(result)

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
                count += 2 + data_length
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
                    # element ~ 75 bytes -> <length><element>
                    result += int_to_little_endian(length, 1)
                elif length <= 255:
                    # element 76 ~ 255 bytes -> <OP_PUSHDATA1><length1><element>
                    result += int_to_little_endian(OP_PUSHDATA1, 1)
                    result += int_to_little_endian(length, 1)
                elif length <= 520:
                    # element 256 ~ 520 bytes -> <OP_PUSHDATA2><length2><element>
                    result += int_to_little_endian(OP_PUSHDATA2, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')

                result += cmd_i
        return result

    def serialize(self) -> bytes:
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z: int) -> bool:
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

                # parse RedeemScript
                # check if cmds = [OP_HASH160, <hash bytes>, OP_EQUAL]
                if len(cmds) == 3 and cmds[0] == 0xa9 and isinstance(
                        cmds[1], bytes) and len(
                            cmds[1]) == 20 and cmds[2] == 0x87:
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    redeem_script = encode_varint(len(cmd_i)) + cmd_i
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        '''
        Returns whether this follows
        [OP_DUP, OP_HASH160, <20 byte hash>, OP_EQUALVERIFY, OP_CHECKSIG]
        pattern.
        '''
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 and self.cmds[
            1] == 0xa9 and isinstance(self.cmds[2], bytes) and len(
                self.cmds[2]
            ) == 20 and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_pubkey(self):
        '''
        Returns whether this follows
        [OP_HASH160, <20 byte hash>, OP_EQUAL]
        pattern.
        '''
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 and isinstance(
            self.cmds[1], bytes) and len(
                self.cmds[1]) == 20 and self.cmds[2] == 0x87


def p2pkh_script(h160: bytes) -> Script:
    '''Takes a hash160 and returns the p2pkh ScriptPubKey'''
    # OP_DUP, OP_HASH160, h160: bytes, OP_EQUALVERIFY, OP_CHECKSIG
    return Script([0x76, 0xa9, h160, 0x88, 0xac])
