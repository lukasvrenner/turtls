use crate::big_int::BigInt;
use core::ops::{Add, Div, Mul, Sub};

#[derive(Debug)]
pub struct GreaterThanMod;

impl core::fmt::Display for GreaterThanMod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "input is larger than modulus")
    }
}

// TODO: uncomment the following line once stabilized
// impl core::error::Error for GreaterThanMod {}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
/// A big integer with the invariant that its value is less than its modulus
pub struct FieldElement(BigInt<4>);

impl FieldElement {
    pub const MODULUS: Self = Self(BigInt::new([
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
    ]));

    pub const ZERO: Self = Self(BigInt::ZERO);

    pub const MIN: Self = Self(BigInt::MIN);

    pub const MAX: Self = Self::MODULUS;

    /// Returns the multiplicative inverse of `self`.
    ///
    /// This value has the property that `self.inverse() * self == 1`
    pub fn inverse(self) -> Self {
        let mut y1 = Self(BigInt::from([
            0x0000000000000001,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ]));
        let mut y2 = Self::ZERO;
        let mut i = Self::MODULUS;
        let mut j = self;
        while j > Self::ZERO {
            let (quotient, remainder) = i / j;
            let y = y2 - (y1 * quotient);
            i = j;
            j = remainder;
            y2 = y1;
            y1 = y;
        }
        y2
    }

    pub fn count_digits(&self) -> usize {
        self.0.count_digits()
    }
}

impl Add for FieldElement {
    type Output = Self;
    /// Performs constant-time addition modulo [`MODULUS`](Self::MODULUS)
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0) - Self::MODULUS
    }
}

impl Sub for FieldElement {
    type Output = Self;
    /// Performs constant-time subtraction modulo [`MODULUS`](Self::MODULUS)
    fn sub(self, rhs: Self) -> Self::Output {
        let (difference, carry) = self.0.overflowing_sub(rhs.0);
        Self(difference + Self::MODULUS.0 * carry)
    }
}

// TODO: use montgomery field for more efficient modular multiplication
impl Mul for FieldElement {
    type Output = Self;
    /// Performs subtraction modulo [`MODULUS`](Self::MODULUS)
    ///
    // TODO: fix this doc link
    /// WARNING: because [`BigInt::div`](crate::big_int::BigInt::div) is not yet constant-time, neither is this operation
    fn mul(self, rhs: Self) -> Self::Output {
        Self(
            (((self.0 * rhs.0) / Self::MODULUS.0.into()).1)[..4]
                .try_into()
                .unwrap(),
        )
    }
}

impl Div for FieldElement {
    type Output = (Self, Self);
    fn div(self, rhs: Self) -> Self::Output {
        let (quotient, remainder) = self.0 / rhs.0;
        // guaranteed to be less than `Self::MODULUS`
        (Self(quotient), Self(remainder))
    }
}

impl From<BigInt<4>> for FieldElement {
    fn from(value: BigInt<4>) -> Self {
        Self((value / Self::MODULUS.0).1)
    }
}

pub struct Point(pub FieldElement, pub FieldElement);

impl Point {
    pub const G: Point = Point(
        FieldElement(BigInt::new([
            0xf4a13945d898c296,
            0x77037d812deb33a0,
            0xf8bce6e563a440f2,
            0x6b17d1f2e12c4247,
        ])),
        FieldElement(BigInt::new([
            0xcbb6406837bf51f5,
            0x2bce33576b315ece,
            0x8ee7eb4a7c0f9e16,
            0x4fe342e2fe1a7f9b,
        ])),
    );
    pub fn mul_scalar(&self, scalar: FieldElement) -> Self {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::big_int::BigInt;

    use super::FieldElement;

    #[test]
    fn inverse() {
        // let a = FieldElement(BigInt::from([
        //     0x0123456789abcdef,
        //     0xfedcba9876543210,
        //     0x0123456789abcdef,
        //     0xfedcba9876543210,
        // ]));
        // let inverse = a.inverse();
        // let one = FieldElement(BigInt::from([
        //     0x0000000000000001,
        //     0x0000000000000000,
        //     0x0000000000000000,
        //     0x0000000000000000,
        // ]));
        // assert_eq!(a * inverse, one);
    }
}
