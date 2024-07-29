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
#[derive(Default, Clone, Copy)]
pub struct BigInt<const N: usize> {
    pub(super) digits: UBigInt<N>,
    /// Determines whether the value is positive or negative
    is_negative: bool,
}

impl<const N: usize> BigInt<N> {
    pub const ZERO: Self = Self { digits: UBigInt::ZERO, is_negative: false };

    pub const ONE: Self = Self { digits: UBigInt::ZERO, is_negative: false };

    pub const MAX: Self = Self { digits: UBigInt::MAX, is_negative: false };
    pub const MIN: Self = Self { digits: UBigInt::MIN, is_negative: true };

    /// Returns the number of digits in `self`. This is value is equal to `N`
    pub fn len(&self) -> usize {
        N
    }

    /// Returns the additive inverse of `self`.
    ///
    /// This is the equivalent to multiplying `self` by -1
    pub fn neg(&self) -> Self {
        Self { digits: self.digits, is_negative: !self.is_negative }
    }

    /// converts `self` to its additive inverse
    ///
    /// This is the equivalent to multiplying `self` by -1
    pub fn neg_assign(&mut self) {
        self.is_negative = !self.is_negative
    }

    pub fn add_assign(&mut self, rhs: &Self) {
        let overflowed = self.digits.overflowing_add_assign(&rhs.digits);
        self.is_negative ^= overflowed;
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.add_assign(&rhs);
        buf
    }

    pub fn sub_assign(&mut self, rhs: &Self) {
        let overflowed = self.digits.overflowing_sub_assign(&rhs.digits);
        self.is_negative ^= overflowed
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.sub_assign(&rhs);
        buf
    }

    #[inline]
    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    #[inline]
    pub fn is_positive(&self) -> bool {
        !self.is_negative
    }
}

impl<const N: usize> From<UBigInt<N>> for BigInt<N> {
    fn from(value: UBigInt<N>) -> Self {
        Self { digits: value, is_negative: false }
    }
}
