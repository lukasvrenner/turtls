//! This module provides large signed integers.
//!
//! For unsigned integers, use [`UBigInt`](`super::BigInt`).
use super::UBigInt;
/// A signed integer of size `N`.
///
/// Unlike builting integers, [`BigInt<N>::MAX`] is the same size as [`UBigInt<N>::MAX`].
///
/// Internally, [`BigInt<N>`] is a little-endian [`[u6u; N]`]
/// and it represents negative numbers using two's compliment.
#[derive(Default, Clone, Copy, Eq, Debug)]
pub struct BigInt<const N: usize> {
    pub(super) digits: UBigInt<N>,
    /// Determines whether the value is positive or negative.
    is_negative: bool,
}

impl<const N: usize> BigInt<N> {
    pub const ZERO: Self = Self { digits: UBigInt::ZERO, is_negative: false };

    pub const ONE: Self = Self { digits: UBigInt::ONE, is_negative: false };
    pub const NEG_ONE: Self = Self { digits: UBigInt::MAX, is_negative: true };

    pub const MAX: Self = Self { digits: UBigInt::MAX, is_negative: false };

    /// The minimum-representable value for [`BigInt<N>`].
    ///
    /// The absolute value of [`BigInt<N>::MIN`] is 1 more than [`BigInt<N>::MAX`].
    /// This causes a weird quirk where [`BigInt<N>::MIN.neg()`] equals [`BigInt<N>::MIN`].
    pub const MIN: Self = Self { digits: UBigInt::MIN, is_negative: true };

    /// Returns the number of digits in `self`. This is value is equal to `N`
    pub fn len(&self) -> usize {
        N
    }

    /// Returns the additive inverse of `self`.
    ///
    /// This is the equivalent to multiplying `self` by -1.
    pub fn neg(&self) -> Self {
        let mut buf = *self;
        buf.neg_assign();
        buf
    }

    /// Converts `self` to its additive inverse
    ///
    /// This is the equivalent to multiplying `self` by -1.
    pub fn neg_assign(&mut self) {
        self.not_assign();
        self.add_assign(&Self::ONE);
    }

    /// modifies `self` to equal `self` + `rhs`
    ///
    /// If `self` + `rhs` is greater than `BigInt::MAX`, the addition wraps around.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn add_assign(&mut self, rhs: &Self) {
        let overflowed = self.digits.overflowing_add_assign(&rhs.digits);
        self.is_negative ^= overflowed ^ rhs.is_negative;
    }

    /// Adds `self` and `rhs`, returning the result.
    ///
    /// If `self` + `rhs` is greater than `BigInt::MAX`, the addition wraps around.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.add_assign(&rhs);
        buf
    }

    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn sub_assign(&mut self, rhs: &Self) {
        let overflowed = self.digits.overflowing_sub_assign(&rhs.digits);
        self.is_negative ^= overflowed ^ rhs.is_negative;
    }

    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.sub_assign(&rhs);
        buf
    }

    /// Returns `true` if `self` is negative, otherwise `false`
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    #[inline]
    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    /// Returns `true` if `self` is positive, otherwise `false`
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    #[inline]
    pub fn is_positive(&self) -> bool {
        !self.is_negative && self.digits != Self::ZERO.digits
    }

    /// Converts `self` into its one's compliment
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn not_assign(&mut self) {
        self.digits.not_assign();
        self.is_negative = !self.is_negative;
    }

    /// Returns the one's compliment of `self`
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn not(&self) -> Self {
        let mut buf = *self;
        buf.not_assign();
        buf
    }
}

impl<const N: usize> core::cmp::PartialEq for BigInt<N> {
    fn eq(&self, other: &Self) -> bool {
        self.digits == other.digits && self.is_negative == other.is_negative
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}

impl<const N: usize> PartialOrd for BigInt<N> {
    fn lt(&self, other: &Self) -> bool {
        self.sub(other).is_negative
    }

    fn le(&self, other: &Self) -> bool {
        !self.gt(other)
    }

    fn gt(&self, other: &Self) -> bool {
        other.sub(self).is_negative
    }

    fn ge(&self, other: &Self) -> bool {
        !self.lt(other)
    }

    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Ord for BigInt<N> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let cmped = self.sub(other);
        match cmped.is_negative {
            true => core::cmp::Ordering::Greater,
            false if self.digits == other.digits => core::cmp::Ordering::Equal,
            false => core::cmp::Ordering::Less,
        }
    }
}

impl<const N: usize> From<UBigInt<N>> for BigInt<N> {
    fn from(value: UBigInt<N>) -> Self {
        Self { digits: value, is_negative: false }
    }
}

#[cfg(test)]
mod tests {
    use super::BigInt;

    #[test]
    fn cmp() {
        assert_eq!(BigInt::<4>::ZERO, BigInt::<4>::ZERO);
        assert_ne!(BigInt::<4>::ZERO, BigInt::ONE);

        assert!(BigInt::<4>::ZERO > BigInt::NEG_ONE);
        assert!(BigInt::<4>::NEG_ONE < BigInt::ZERO);
        assert!(BigInt::<4>::ONE > BigInt::NEG_ONE);
    }

    #[test]
    fn add() {
        assert_eq!(BigInt::<4>::ONE.add(&BigInt::NEG_ONE), BigInt::ZERO);
        assert_eq!(BigInt::<4>::MAX.add(&BigInt::ONE), BigInt::MIN);
        assert_eq!(BigInt::<4>::ZERO.add(&BigInt::ONE), BigInt::ONE);
    }

    #[test]
    fn sub() {
        assert_eq!(BigInt::<4>::MIN.sub(&BigInt::ONE), BigInt::MAX);
        assert_eq!(BigInt::<4>::MIN.sub(&BigInt::MAX), BigInt::ONE);
        assert_eq!(BigInt::<4>::ZERO.sub(&BigInt::ONE), BigInt::NEG_ONE);
    }

    #[test]
    fn neg() {
        assert_eq!(BigInt::<4>::ONE.neg(), BigInt::NEG_ONE);
        assert_eq!(BigInt::<4>::NEG_ONE.neg(), BigInt::ONE);
        assert_eq!(BigInt::<4>::ZERO.neg(), BigInt::ZERO);
        assert_eq!(BigInt::<4>::MIN.neg(), BigInt::MIN);
    }
}
