import hashlib
from typing import Callable

from src.helper import hash160, hash256
from src.secp256k1 import S256Point, Signature

OP_PUSHDATA1 = 76
OP_PUSHDATA2 = 77
OP_IF = 99
OP_NOTIF = 100
OP_ELSE = 103
OP_ENDIF = 104
OP_TOALTSTACK = 107
OP_FROMALTSTACK = 108
OP_CHECKSIG = 172
OP_CHECKSIGVERIFY = 173
OP_CHECKMULTISIG = 174
OP_CHECKMULTISIGVERIFY = 175

# https://en.bitcoin.it/wiki/Script


def encode_num(num: int) -> bytes:
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8
    # if the top bit is set,
    # for negative numbers we ensure that the top bit is set
    # for positive numbers we ensure that the top bit is not set
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element: bytes) -> int:
    if element == b'':
        return 0
    # reverse for big endian
    big_endian = element[::-1]
    # top bit being 1 means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result


def op_0(stack: list) -> bool:
    stack.append(encode_num(0))
    return True


def op_1negate(stack: list) -> bool:
    stack.append(encode_num(-1))
    return True


def op_1(stack: list) -> bool:
    stack.append(encode_num(1))
    return True


def op_2(stack: list) -> bool:
    stack.append(encode_num(2))
    return True


def op_3(stack: list) -> bool:
    stack.append(encode_num(3))
    return True


def op_4(stack: list) -> bool:
    stack.append(encode_num(4))
    return True


def op_5(stack: list) -> bool:
    stack.append(encode_num(5))
    return True


def op_6(stack: list) -> bool:
    stack.append(encode_num(6))
    return True


def op_7(stack: list) -> bool:
    stack.append(encode_num(7))
    return True


def op_8(stack: list) -> bool:
    stack.append(encode_num(8))
    return True


def op_9(stack: list) -> bool:
    stack.append(encode_num(9))
    return True


def op_10(stack: list) -> bool:
    stack.append(encode_num(10))
    return True


def op_11(stack: list) -> bool:
    stack.append(encode_num(11))
    return True


def op_12(stack: list) -> bool:
    stack.append(encode_num(12))
    return True


def op_13(stack: list) -> bool:
    stack.append(encode_num(13))
    return True


def op_14(stack: list) -> bool:
    stack.append(encode_num(14))
    return True


def op_15(stack: list) -> bool:
    stack.append(encode_num(15))
    return True


def op_16(stack: list) -> bool:
    stack.append(encode_num(16))
    return True


def op_nop(stack: list) -> bool:
    return True


def base_if_parser(stack: list, items: list, true_items: list,
                   false_items: list) -> bool:
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (OP_IF, OP_NOTIF):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == OP_ELSE:
            current_array = false_items
        elif item == OP_ENDIF:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    return found


def op_if(stack: list, items: list) -> bool:
    # 99: If the top stack value is not False, the statements are executed. The top stack value is removed.
    true_items: list = []
    false_items: list = []
    found = base_if_parser(stack, items, true_items, false_items)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items
    return True


def op_notif(stack: list, items: list) -> bool:
    # 100: If the top stack value is False, the statements are executed. The top stack value is removed.
    true_items: list = []
    false_items: list = []
    found = base_if_parser(stack, items, true_items, false_items)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True


def op_verify(stack: list) -> bool:
    # 105: Marks transaction as invalid if top stack value is not true. The top stack value is removed.
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True


def op_return(stack: list) -> bool:
    # 106: Marks transaction as invalid.
    return False


def op_toaltstack(stack: list, altstack: list) -> bool:
    # 107: Puts the input onto the top of the alt stack. Removes it from the main stack.
    if len(stack) < 1:
        return False
    altstack.append(stack.pop())
    return True


def op_fromaltstack(stack: list, altstack: list) -> bool:
    # 108: Puts the input onto the top of the main stack. Removes it from the alt stack.
    if len(altstack) < 1:
        return False
    stack.append(altstack.pop())
    return True


def op_2drop(stack: list) -> bool:
    # 109: Removes the top two stack items.
    if len(stack) < 2:
        return False
    stack.pop()
    stack.pop()
    return True


def op_2dup(stack: list) -> bool:
    # 110: Duplicates the top two stack items.
    if len(stack) < 2:
        return False
    stack.extend(stack[-2:])
    return True


def op_3dup(stack: list) -> bool:
    # 111: Duplicates the top three stack items.
    if len(stack) < 3:
        return False
    stack.extend(stack[-3:])
    return True


def op_2over(stack: list) -> bool:
    # 112: Copies the pair of items two spaces back in the stack to the front.
    if len(stack) < 4:
        return False
    stack.extend(stack[-4:-2])
    return True


def op_2rot(stack: list) -> bool:
    # 113: The fifth and sixth items back are moved to the top of the stack.
    if len(stack) < 6:
        return False
    stack[:] = stack[:-6] + stack[-4:] + stack[-6:-4]
    return True


def op_2swap(stack: list) -> bool:
    # 114: Swaps the top two pairs of items.
    if len(stack) < 4:
        return False
    stack[-4:] = stack[-2:] + stack[-4:-2]
    return True


def op_ifdup(stack: list) -> bool:
    # 115: If the top stack value is not 0, duplicate it.
    if len(stack) < 1:
        return False
    if decode_num(stack[-1]) != 0:
        stack.append(stack[-1])
    return True


def op_depth(stack: list) -> bool:
    # 116: Puts the number of stack items onto the stack.
    stack.append(encode_num(len(stack)))
    return True


def op_drop(stack):
    # 117: Removes the top stack item.
    if len(stack) < 1:
        return False
    stack.pop()
    return True


def op_dup(stack: list) -> bool:
    # 118: Duplicates the top stack item.
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_nip(stack: list) -> bool:
    # 119: Removes the second-to-top stack item.
    if len(stack) < 2:
        return False
    stack[-2:] = stack[-1:]
    return True


def op_over(stack: list) -> bool:
    # 120: Copies the second-to-top stack item to the top.
    if len(stack) < 2:
        return False
    stack.append(stack[-2])
    return True


def op_pick(stack: list) -> bool:
    # 121: The item n back in the stack is copied to the top.
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    stack.append(stack[-n - 1])
    return True


def op_roll(stack: list) -> bool:
    # 122: The item n back in the stack is moved to the top.
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    if n == 0:
        return True
    stack.append(stack.pop(-n - 1))
    return True


def op_rot(stack: list) -> bool:
    # 123: The 3rd item down the stack is moved to the top.
    if len(stack) < 3:
        return False
    stack.append(stack.pop(-3))
    return True


def op_swap(stack: list) -> bool:
    # 124: The top two items on the stack are swapped.
    if len(stack) < 2:
        return False
    stack.append(stack.pop(-2))
    return True


def op_tuck(stack: list) -> bool:
    # 125: The item at the top of the stack is copied and inserted before the second-to-top item.
    if len(stack) < 2:
        return False
    stack.insert(-2, stack[-1])
    return True


def op_size(stack: list) -> bool:
    # 130: Pushes the string length of the top element of the stack (without popping it).
    if len(stack) < 1:
        return False
    stack.append(encode_num(len(stack[-1])))
    return True


def op_equal(stack: list) -> bool:
    # 135: Returns 1 if the inputs are exactly equal, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_equalverify(stack: list) -> bool:
    # 136: Same as OP_EQUAL, but runs OP_VERIFY afterward.
    return op_equal(stack) and op_verify(stack)


def op_1add(stack: list) -> bool:
    # 139: 1 is added to the input.
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element + 1))
    return True


def op_1sub(stack: list) -> bool:
    # 140: 1 is subtracted from the input.
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element - 1))
    return True


def op_negate(stack: list) -> bool:
    # 143: The sign of the input is flipped.
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(-element))
    return True


def op_abs(stack: list) -> bool:
    # 144: The input is made positive.
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(abs(element)))
    return True


def op_not(stack: list) -> bool:
    # 145: If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_0notequal(stack: list) -> bool:
    # 146: Returns 0 if the input is 0. 1 otherwise.
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_add(stack: list) -> bool:
    # 147: a is added to b.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element1 + element2))
    return True


def op_sub(stack: list) -> bool:
    # 148: b is subtracted from a.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 - element1))
    return True


def op_mul(stack: list) -> bool:
    # 149: a is multiplied by b. disabled.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 * element1))
    return True


def op_booland(stack: list) -> bool:
    # 154: If both a and b are not 0, the output is 1. Otherwise 0.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 and element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_boolor(stack: list) -> bool:
    # 155: If a or b is not 0, the output is 1. Otherwise 0.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 or element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequal(stack: list) -> bool:
    # 156: Returns 1 if the numbers are equal, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequalverify(stack: list) -> bool:
    # 157: Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    return op_numequal(stack) and op_verify(stack)


def op_numnotequal(stack: list) -> bool:
    # 158: Returns 1 if the numbers are not equal, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_lessthan(stack: list) -> bool:
    # 159: Returns 1 if a is less than b, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 < element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthan(stack: list) -> bool:
    # 160: Returns 1 if a is greater than b, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 > element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_lessthanorequal(stack: list) -> bool:
    # 161: Returns 1 if a is less than or equal to b, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 <= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthanorequal(stack: list) -> bool:
    # 162: Returns 1 if a is greater than or equal to b, 0 otherwise.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 >= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_min(stack: list) -> bool:
    # 163: Returns the smaller of a and b.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 < element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_max(stack: list) -> bool:
    # 164: Returns the larger of a and b.
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 > element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_within(stack: list) -> bool:
    # 165: Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
    if len(stack) < 3:
        return False
    maximum = decode_num(stack.pop())
    minimum = decode_num(stack.pop())
    element = decode_num(stack.pop())
    if minimum <= element < maximum:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_ripemd160(stack: list) -> bool:
    # 166: The input is hashed using RIPEMD-160.
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new('ripemd160', element).digest())
    return True


def op_sha1(stack: list) -> bool:
    # 167: The input is hashed using SHA-1.
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha1(element).digest())
    return True


def op_sha256(stack: list) -> bool:
    # 168: The input is hashed using SHA-256.
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True


def op_hash160(stack: list) -> bool:
    # 169: The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash160(element))
    return True


def op_hash256(stack: list) -> bool:
    # 170: The input is hashed two times with SHA-256.
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True


def op_checksig(stack: list, z) -> bool:
    # 172:
    if len(stack) < 2:
        return False
    sec_pubkey = stack.pop()
    der_sig = stack.pop()
    try:
        pubkey = S256Point.parse(sec_pubkey)
        sig = Signature.parse(der_sig)
    except (ValueError, SyntaxError):
        return False
    if pubkey.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_checksigverify(stack: list, z) -> bool:
    # 173: Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
    return op_checksig(stack, z) and op_verify(stack)


def op_checkmultisig(stack, z):
    # 174
    raise NotImplementedError


def op_checkmultisigverify(stack: list, z) -> bool:
    # 175: Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
    return op_checkmultisig(stack, z) and op_verify(stack)


def op_checklocktimeverify(stack, locktime, sequence):
    # 177
    if sequence == 0xffffffff:
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if element < 500000000 and locktime > 500000000:
        return False
    if locktime < element:
        return False
    return True


def op_checksequenceverify(stack, version, sequence):
    # 178
    if sequence & (1 << 31) == (1 << 31):
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if element & (1 << 31) == (1 << 31):
        if version < 2:
            return False
        elif sequence & (1 << 31) == (1 << 31):
            return False
        elif element & (1 << 22) != sequence & (1 << 22):
            return False
        elif element & 0xffff > sequence & 0xffff:
            return False
    return True


OP_CODE_FUNCTIONS: dict[int, Callable] = {
    0: op_0,
    79: op_1negate,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    97: op_nop,
    99: op_if,
    100: op_notif,
    105: op_verify,
    106: op_return,
    107: op_toaltstack,
    108: op_fromaltstack,
    109: op_2drop,
    110: op_2dup,
    111: op_3dup,
    112: op_2over,
    113: op_2rot,
    114: op_2swap,
    115: op_ifdup,
    116: op_depth,
    117: op_drop,
    118: op_dup,
    119: op_nip,
    120: op_over,
    121: op_pick,
    122: op_roll,
    123: op_rot,
    124: op_swap,
    125: op_tuck,
    130: op_size,
    135: op_equal,
    136: op_equalverify,
    139: op_1add,
    140: op_1sub,
    143: op_negate,
    144: op_abs,
    145: op_not,
    146: op_0notequal,
    147: op_add,
    148: op_sub,
    149: op_mul,
    154: op_booland,
    155: op_boolor,
    156: op_numequal,
    157: op_numequalverify,
    158: op_numnotequal,
    159: op_lessthan,
    160: op_greaterthan,
    161: op_lessthanorequal,
    162: op_greaterthanorequal,
    163: op_min,
    164: op_max,
    165: op_within,
    166: op_ripemd160,
    167: op_sha1,
    168: op_sha256,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig,
    173: op_checksigverify,
    174: op_checkmultisig,
    175: op_checkmultisigverify,
    176: op_nop,
    177: op_checklocktimeverify,
    178: op_checksequenceverify,
    179: op_nop,
    180: op_nop,
    181: op_nop,
    182: op_nop,
    183: op_nop,
    184: op_nop,
    185: op_nop,
}

OP_CODE_NAMES: dict[int, str] = {
    0: 'OP_0',
    OP_PUSHDATA1: 'OP_PUSHDATA1',
    OP_PUSHDATA2: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    130: 'OP_SIZE',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    149: 'OP_MUL',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}
