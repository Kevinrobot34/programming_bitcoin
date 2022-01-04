from __future__ import annotations

import hashlib
import hmac
from random import randint

from src.ecc import FieldElement, Point


class Signature:
    def __init__(self, r: int, s: int) -> None:
        self.r = r
        self.s = s

    def __repr__(self) -> str:
        return f'Signature({self.r}, {self.s})'

    def der(self) -> bytes:
        rbin = self.r.to_bytes(32, 'big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin

        sbin = self.s.to_bytes(32, 'big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin

        result = bytes([2, len(rbin)]) + rbin
        result += bytes([2, len(sbin)]) + sbin
        result = bytes([0x30, len(result)]) + result
        return result


class PrivateKey:
    def __init__(self, secret: int) -> None:
        self.secret: int = secret
        self.public_point: S256Point = secret * G  # public key

    def hex(self) -> str:
        return f'{self.secret:x}'.zfill(64)

    def sign(self, z: int) -> Signature:
        # prepare random number k
        # k = self.random_k()
        k = self.deterministic_k(z)

        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    @staticmethod
    def random_k():
        # simple implementation
        return randint(0, N - 1)

    def deterministic_k(self, z: int) -> int:
        # following RFC 6979: https://datatracker.ietf.org/doc/html/rfc6979
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()


class S256Field(FieldElement):
    '''
    32 bytes number with modulo P = 2**256 - 2**32 - 977
    '''
    def __init__(self, num: int, prime=None) -> None:
        prime = P
        super().__init__(num=num, prime=prime)

    def __str__(self) -> str:
        return f'{self.num:x}'.zfill(64)  # 32 bytes number as hex

    def sqrt(self) -> S256Field:
        return self**((P + 1) // 4)


class S256Point(Point):
    '''
    Points generated from G
    - Main use case is for Public Point in ECDSA
    - Order of this group is N (N * G = 0)
    '''
    def __init__(self, x, y, a=None, b=None) -> None:
        a = S256Field(A)
        b = S256Field(B)
        if isinstance(x, int) and isinstance(y, int):
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            # for zero-point
            super().__init__(x, y, a, b)

    def __rmul__(self, coefficient: int) -> S256Point:
        coefficient %= N
        return super().__rmul__(coefficient)

    def verify(self, z, sig: Signature) -> bool:
        # check if uG + vP is equal to sig.r
        # self: P
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r

    def sec(self, compressed: bool = True) -> bytes:
        # return SEC format bytes
        if compressed:
            # compressed format : return 33 bytes data
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            # uncompressed format : return 65 bytes data
            return b'\x04' + self.x.num.to_bytes(32, 'big') \
                + self.y.num.to_bytes(32, 'big')

    @classmethod
    def parse(cls, sec_bin: bytes) -> S256Point:
        if sec_bin[0] == 4:
            # uncompressed SEC format
            return S256Point(x=int.from_bytes(sec_bin[1:33], 'big'),
                             y=int.from_bytes(sec_bin[33:65], 'big'))

        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:33], 'big'))
        y2 = x**3 + S256Field(A) * x + S256Field(B)
        y = y2.sqrt()
        if y.num % 2 == 0:
            y_even = y
            y_odd = S256Field(P - y.num)
        else:
            y_even = S256Field(P - y.num)
            y_odd = y

        return S256Point(x, y_even if is_even else y_odd)


# define constant
P = 2**256 - 2**32 - 977  # 256bit(32bytes)
A = 0
B = 7
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
G = S256Point(
    0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,  # 256bit(32bytes)
    0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8,  # 256bit(32bytes)
)
