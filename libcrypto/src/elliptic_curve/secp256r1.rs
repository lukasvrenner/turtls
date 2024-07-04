use crate::big_int::BigInt;
use core::ops::{Add, Mul, Sub};

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
        0xffffffff00000000,
        0xffffffffffffffff,
        0xbce6faada7179e84,
        0xf3b9cac2fc632551,
    ]));

    /// Returns the multiplicative inverse of `self`.
    ///
    /// This value has the property that `self.inverse() * self == 1`
    pub fn inverse(&self) -> Self {
        todo!();
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
        Self(((self.0 * rhs.0) / Self::MODULUS.0.into()).1)
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
            0x6b17d1f2e12c4247,
            0xf8bce6e563a440f2,
            0x77037d812deb33a0,
            0xf4a13945d898c296,
        ])),
        FieldElement(BigInt::new([
            0x4fe342e2fe1a7f9b,
            0x8ee7eb4a7c0f9e16,
            0x2bce33576b315ece,
            0xcbb6406837bf51f5,
        ])),
    );
    pub fn mul_scalar(&self, scalar: FieldElement) -> Self {
        todo!();
    }
}
