//! The home to [`BigInt`].
use super::UBigInt;
/// A signed integer of size `N * 64` bits, plus 1 sign byte.
///
/// Unlike for built-in integers, [`BigInt<N>::MAX`] is the same size as [`UBigInt<N>::MAX`].
///
/// Internally, [`BigInt<N>`] is a little-endian `[u64; N]`.
/// Negative numbers are represented using the [two's compliment](https://en.wikipedia.org/wiki/Two%27s_complement) number scheme.
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Hash)]
pub struct BigInt<const N: usize> {
    pub(crate) digits: UBigInt<N>,
    is_negative: bool,
}

impl<const N: usize> BigInt<N> {
    /// Represents the value `0`
    ///
    /// This is the equivalent to [`UBigInt<N>::ZERO`].
    pub const ZERO: Self = Self {
        digits: UBigInt::ZERO,
        is_negative: false,
    };

    /// Represents the value `1`
    pub const ONE: Self = Self {
        digits: UBigInt::ONE,
        is_negative: false,
    };

    /// Represents the value `-1`
    pub const NEG_ONE: Self = Self {
        digits: UBigInt::MAX,
        is_negative: true,
    };

    /// The maximum-representable value for [`BigInt<N>`].
    ///
    /// This is the equivalent to [`UBigInt<N>::MAX`].
    pub const MAX: Self = Self {
        digits: UBigInt::MAX,
        is_negative: false,
    };

    /// The minimum-representable value for [`BigInt<N>`].
    ///
    /// The absolute value of [`BigInt<N>::MIN`] is 1 more than [`BigInt<N>::MAX`].
    ///
    /// This particular value has some weird quirks:
    /// * Calling [`BigInt::neg()`] on it returns itself.
    /// * Calling [`BigInt::abs()`] on it returns [`Self::ZERO`].
    ///
    /// # Examples
    /// ```
    /// use libcrypto::big_int::BigInt;
    ///
    /// assert_eq!(BigInt::<4>::MIN.neg(), BigInt::MIN);
    /// assert_eq!(BigInt::<4>::MIN.abs(), BigInt::ZERO);
    /// ```
    pub const MIN: Self = Self {
        digits: UBigInt::MIN,
        is_negative: true,
    };

    /// Returns the number of digits `self` can store.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns the additive inverse of `self`.
    ///
    /// This is the equivalent to multiplying `self` by `-1`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Converts `self` to its additive inverse.
    ///
    /// This is the equivalent to multiplying `self` by `-1`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn neg_assign(&mut self) {
        self.not_assign();
        self.add_assign(&Self::ONE);
    }

    /// Adds `self` and `rhs`, storing the renult in `self`.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn add_assign(&mut self, rhs: &Self) {
        let overflowed = self.digits.overflowing_add_assign(&rhs.digits);
        self.is_negative ^= overflowed ^ rhs.is_negative;
    }

    /// Adds `self` and `rhs`, returning the result.
    ///
    /// If `self` + `rhs` is greater than `BigInt::MAX`, the addition wraps around.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.add_assign(rhs);
        buf
    }

    /// Subtracts `rhs` from `self`, storing the result in `self`.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn sub_assign(&mut self, rhs: &Self) {
        let overflowed = self.digits.overflowing_sub_assign(&rhs.digits);
        self.is_negative ^= overflowed ^ rhs.is_negative;
    }

    /// Subtracts `rhs` from `self`, returning the result.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.sub_assign(rhs);
        buf
    }

    /// Returns `true` if `self` is negative, otherwise `false`
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    #[inline]
    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    /// Returns `true` if `self` is positive, otherwise `false`
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    #[inline]
    pub fn is_positive(&self) -> bool {
        !self.is_negative && *self != Self::ZERO
    }

    /// Converts `self` into its one's compliment
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn not_assign(&mut self) {
        self.digits.not_assign();
        self.is_negative = !self.is_negative;
    }

    /// Returns the one's compliment of `self`
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn not(&self) -> Self {
        let mut buf = *self;
        buf.not_assign();
        buf
    }

    /// Performs a bitwise `XOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn xor_assign(&mut self, rhs: &Self) {
        self.digits.xor_assign(&rhs.digits);
        self.is_negative ^= rhs.is_negative;
    }

    /// Performs a bitwise `XOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn xor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.xor_assign(rhs);
        buf
    }

    /// Converts `self` into its absolute value.
    ///
    /// Note: the returned value will be positive for all input valuess *except* [`Self::MIN`]
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn abs_assign(&mut self) {
        let temp = *self;
        self.neg_assign();
        self.xor_assign(&temp);
    }

    /// Returns the absolute value of `self`.
    ///
    /// Note: the returned value will be positive for all input valuess *except* [`Self::MIN`]
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn abs(&self) -> Self {
        self.xor(&self.neg())
    }

    pub fn resize<const O: usize>(self) -> BigInt<O> {
        BigInt {
            digits: self.digits.resize(),
            is_negative: self.is_negative,
        }
    }
}

macro_rules! impl_big_int {
    ($n:literal) => {
        impl BigInt<$n> {
            /// Divides `self` by `rhs`, returning the quotient and the remainder.
            ///
            /// # Panics
            /// This function will panic if `divisor == Self::ZERO`.
            ///
            /// # Constant-timedness
            /// TODO: document constant-timedness
            pub fn div(&self, rhs: &Self) -> (Self, Self) {
                let (quotient, remainder) = self.digits.div(&rhs.digits);
                let quotient = Self {
                    digits: quotient,
                    is_negative: (self.is_negative ^ rhs.is_negative)
                        && *self != Self::ZERO
                        && *rhs != Self::ZERO,
                };
                let remainder = Self {
                    digits: remainder,
                    is_negative: self.is_negative,
                };
                (quotient, remainder)
            }

            /// Divides `self` by `rhs` and stores the result in `self`
            pub fn div_assign(&mut self, rhs: &Self) {
                *self = self.div(rhs).0;
            }

            /// Muliplies `self` and `rhs`, returing the result.
            ///
            /// The product is twice the width of the input, so overflow cannot occur.
            pub fn widening_mul(&self, rhs: &Self) -> BigInt<{ $n * 2 }> {
                let product = self.digits.widening_mul(&rhs.digits);
                BigInt::<{ $n * 2 }> {
                    digits: product,
                    is_negative: (self.is_negative ^ !rhs.is_negative)
                        && *self != Self::ZERO
                        && *rhs != Self::ZERO,
                }
            }
        }
    };
}

impl_big_int!(4);
impl_big_int!(8);

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
        Self {
            digits: value,
            is_negative: false,
        }
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

        let mut one = BigInt::<4>::ONE;
        one.neg_assign();
        assert_eq!(one, BigInt::NEG_ONE);
    }

    #[test]
    fn mul() {
        // Multiplying by zero can be tricky to implement properly
        assert_eq!(BigInt::<4>::ZERO.widening_mul(&BigInt::MIN), BigInt::ZERO);
        assert_eq!(BigInt::<4>::ZERO.widening_mul(&BigInt::ZERO), BigInt::ZERO);
        assert_eq!(
            BigInt::<4>::ZERO.widening_mul(&BigInt::NEG_ONE),
            BigInt::ZERO
        );
        assert_eq!(BigInt::<4>::ZERO.widening_mul(&BigInt::ONE), BigInt::ZERO);
    }
}
