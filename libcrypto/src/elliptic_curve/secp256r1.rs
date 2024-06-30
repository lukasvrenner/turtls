use crate::big_int::BigInt;
use core::ops::{Add, Deref, Mul, Sub};

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
        // todo!()
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
