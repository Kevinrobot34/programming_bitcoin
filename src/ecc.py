from __future__ import annotations


class FieldElement(object):
    def __init__(self, num: int, prime: int) -> None:
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime-1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __str__(self) -> str:
        return f'FieldElement_{self.prime}({self.num})'

    def __eq__(self, other: object) -> bool:
        if other is None or not isinstance(other, FieldElement):
            return False
        return (self.prime == other.prime) and (self.num == other.num)

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __add__(self, other: FieldElement) -> FieldElement:
        if self.prime != other.prime:
            error = 'Cannot add two numbers in different Fields'
            raise TypeError(error)
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other: FieldElement) -> FieldElement:
        if self.prime != other.prime:
            error = 'Cannot subtract two numbers in different Fields'
            raise TypeError(error)
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other: FieldElement) -> FieldElement:
        if self.prime != other.prime:
            error = 'Cannot multiply two numbers in different Fields'
            raise TypeError(error)
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient: int) -> FieldElement:
        num = (coefficient * self.num) % self.prime
        return self.__class__(num, self.prime)

    def __truediv__(self, other: FieldElement) -> FieldElement:
        if self.prime != other.prime:
            error = 'Cannot divide two numbers in different Fields'
            raise TypeError(error)
        other_inv = pow(other.num, self.prime - 2, self.prime)
        num = (self.num * other_inv) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent: int) -> FieldElement:
        exponent %= self.prime - 1
        num = pow(self.num, exponent, self.prime)
        return self.__class__(num, self.prime)


class Point(object):
    def __init__(self, x, y, a, b) -> None:
        self.x = x
        self.y = y
        self.a = a
        self.b = b
        if self.x is None and self.y is None:
            # point at infinity
            return
        # check if point is on the Elliptic Curve: y^2 = x^3 + a*x + b
        if self.y**2 != self.x**3 + self.a * self.x + self.b:
            error = f'({self.x}, {self.y}) is not on the curve'
            raise ValueError(error)

    def __str__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __eq__(self, other: object) -> bool:
        if other is None or not isinstance(other, Point):
            return False
        return (self.x == other.x) and (self.y == other.y) and (
            self.a == other.a) and (self.b == other.b)

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __add__(self, other: Point) -> Point:
        if self.a != other.a or self.b != other.b:
            error = f'Points {self} and {other} are not on the same curve'
            raise TypeError(error)

        # if self or other is point at infinity
        if self.x is None:
            return other
        if other.x is None:
            return self

        if self.x == other.x:
            if self.y != other.y or self.y == 0 * self.x:
                return self.__class__(None, None, self.a, self.b)
            else:
                s = (3 * self.x**2 + self.a) / (2 * self.y)
                x = s**2 - 2 * self.x
                y = s * (self.x - x) - self.y
                return self.__class__(x, y, self.a, self.b)
        else:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient: int) -> Point:
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coefficient:
            if coefficient & 1:
                result += current
            current += current
            coefficient >>= 1
        return result
