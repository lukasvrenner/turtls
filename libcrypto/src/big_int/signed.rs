//! This module provides large signed integers.
//!
//! For unsigned integers, use [`UBigInt`](`super::BigInt`).
use super::UBigInt;
/// A signed integer of size `N`.
///
/// Unlike builting integers, [`BigInt<N>::MAX`] is the same size as [`UBigInt<N>::MAX`].
///
/// Internally, [`BigInt<N>`] is a little-endian [`[u6u; N]`]
/// and it represents negative numbers using two's compliment
pub struct BigInt<const N: usize> {
    value: UBigInt<N>,
    /// Determines whether the value is positive or negative
    pub sign: Sign,
}

impl<const N: usize> BigInt<N> {
    pub const ZERO: Self = Self { value: UBigInt::ZERO, sign: Sign::Positive };
    pub const ONE: Self = Self { value: UBigInt::ZERO, sign: Sign::Positive };
    /// Returns the number of digits in `self`. This is value is equal to `N`
    pub fn len(&self) -> usize {
        N
    }

    /// Returns the additive inverse of `self`.
    ///
    /// This is the equivalent to multiplying `self` by -1
    pub fn neg(&self) -> Self {
        todo!()
    }

    /// converts `self` to its additive inverse
    ///
    /// This is the equivalent to multiplying `self` by -1
    pub fn neg_assign(&mut self) {
        todo!()
    }
}

impl<const N: usize> From<UBigInt<N>> for BigInt<N> {
    fn from(value: UBigInt<N>) -> Self {
        Self { value, sign: Sign::Positive }
    }
}

/// The sign of [`BigInt`]
pub enum Sign {
    /// The [`BigInt`] is positive
    Positive,
    /// The [`BigInt`] is negative
    Negative,
}
