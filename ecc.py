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
    breakpoint()
    sum = a + b
    return sub(sum, MOD)

def sub(a: int, b: int) -> int:
    # assert(a < MOD and b < MOD and a >= 0 and b >= 0)
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
            return None

        if self != rhs:
            # slope = div(sub(rhs.y, self.y), sub(rhs.x, self.x))
            y_diff = sub(rhs.y, self.y)
            x_diff = sub(rhs.x, self.x)
            slope = div(sub(rhs.y, self.y), sub(rhs.x, self.x))
        else:
            # breakpoint()
            slope = mul(self.x, self.x)
            slope = mul(slope, 3)
            slope = add(slope, A)
            temp = mul(2, self.y)
            slope = div(slope, temp)

        x = sqr(slope)
        x = sub(x, self.x)
        x = sub(x, rhs.x)

        y = mul(slope, sub(self.x, x))
        y = sub(y, self.y)
        return Secp256r1(x, y)

    def double(self):
        return self.add(self)

    def __eq__(self, other):
        if not isinstance(other, Secp256r1):
            return NotImplemented
        return self.x == other.x and self.y == other.y


BASE_POINT = Secp256r1(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
K_2 = Secp256r1(0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978, 0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1)
K_3 = Secp256r1(0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c, 0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032)
# TRY_K_3 = K_2.add(BASE_POINT)
# assert(TRY_K_3 == K_3)
# assert(K_3 == BASE_POINT.add(K_2))
assert(K_2 == BASE_POINT.double())
