#!/usr/bin/python

MOD: int = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

def unimplemented():
    print("unimplemented!")
    exit(2)

def mul(a: int, b: int) -> int:
    assert(a < MOD and b < MOD and a >= 0 and b >= 0)
    return (a * b) % MOD

def add(a: int, b: int) -> int:
    assert(a < MOD and b < MOD and a >= 0 and b >= 0)
    return (a + b) % MOD

def sub(a: int, b: int) -> int:
    assert(a < MOD and b < MOD and a >= 0 and b >= 0)
    dif = a - b
    if dif < 0:
        dif += MOD
    return dif

def neg(a: int) -> int:
    assert(a < MOD and a >= 0)
    return sub(0, a)

def sqr(a: int) -> int:
    return mul(a, a)

def div(a: int, b: int) -> int:
    assert(a < MOD and b < MOD and a >= 0 and b >= 0)
    return mul(a, inverse(b))

def inverse(a: int) -> int:
    t = 0
    new_t = 1
    r = MOD
    new_r = a
    while new_r != 0:
        quotient = r // new_r
        remainder = r % new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, remainder
    assert(r == 1)
    if t < 0:
        t += MOD
    assert(t > 0)
    assert t < MOD
    return t

class Secp256r1:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):
        return f"({hex(self.x)}, {hex(self.y)})"

    def neg(self):
        return Secp256r1(self.x, neg(self.y))

    def add(self, rhs):
        if self == None:
            return rhs
        if rhs == None:
            return self

        if self.neg() == rhs:
            print("got None")
            return None

        if self != rhs:
            slope = div(sub(rhs.y, self.y), sub(rhs.x, self.x))
        else:
            slope = unimplemented()
        print(slope)

        x = sqr(slope)
        x = sub(x, self.x)
        x = sub(x, rhs.x)

        y = mul(slope, sub(self.x, rhs.x))

        y = sub(y, self.y)
        return Secp256r1(x, y)

    def double(self):
        self.add(self)


BASE_POINT = Secp256r1(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
K_2 = Secp256r1(0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978, 0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1)
print(K_2.add(BASE_POINT))
