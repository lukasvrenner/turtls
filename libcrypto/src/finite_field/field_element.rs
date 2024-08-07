use core::marker::PhantomData;

use crate::big_int::{BigInt, InputTooLargeError, UBigInt};

use super::FiniteField;
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
/// A big integer with the invariant that its value is less than its modulus
pub struct FieldElement<F: FiniteField>(UBigInt<4>, PhantomData<F>);

impl<F: FiniteField> FieldElement<F> {
    /// Creates a new `FieldElement` from `value`.
    ///
    /// If `value` is greater than `F::MODULUS`, it is properly reduced.
    ///
    /// Because it always performs a division operation, this function is much slower than a simple
    /// type conversion. If higher performance, at the cost of falibility, is necessary, use
    /// [`Self::try_new()`] or its unsafe counterpart, [`Self::new_unchecked()`]
    pub fn new(value: UBigInt<4>) -> Self {
        Self(value.div(&F::MODULUS).1, PhantomData)
    }

    /// Creates a new `FieldElement` without checking if `int` is less than `F::MODULUS`.
    ///
    /// # Safety
    /// `int` must be less than `F::MODULUS`. A violation of this will result in undefined
    /// behavior.
    ///
    /// In most cases, it's better to use the safe version: [`Self::try_new()`]
    pub const unsafe fn new_unchecked(int: UBigInt<4>) -> Self {
        Self(int, PhantomData)
    }

    /// Creates a new `FieldElement` from `int`, returning an `Err` if `int >= F::MODULUS`.
    ///
    /// This is the safe version of [`Self::new_unchecked()`]
    pub fn try_new(int: UBigInt<4>) -> Result<Self, InputTooLargeError> {
        if int >= F::MODULUS {
            return Err(InputTooLargeError);
        };
        // SAFETY: we already checked to guarantee that `int` is less than `F::MODULUS`.
        Ok(unsafe { Self::new_unchecked(int) })
    }

    /// Returns the multiplicative inverse of `self`.
    ///
    /// This value has the property that `self.inverse() * self == 1`
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn inverse(&self) -> Self {
        let mut t = BigInt::ZERO;
        let mut new_t = BigInt::ONE;
        let mut r: BigInt<4> = F::MODULUS.into();
        let mut new_r: BigInt<4> = self.0.into();

        while new_r != BigInt::ZERO {
            let (quotient, remainder) = r.div(&new_r);
            (t, new_t) = (
                new_t,
                t.sub(&BigInt::<4>::from(quotient.widening_mul(&new_t))),
            );
            (r, new_r) = (new_r, remainder);
        }
        debug_assert_eq!(r, BigInt::ONE);
        if t.is_negative() {
            t.add_assign(&F::MODULUS.into())
        }
        debug_assert!(t.is_positive());
        // TODO: is it better to use safe or unsafe version?
        Self::try_new(t.digits).unwrap()
    }

    /// Returns the number of digits in `self`, not counting leading zeros
    ///
    /// # Constant-timedness:
    /// This function is constant-time.
    pub fn count_digits(&self) -> usize {
        self.0.count_digits()
    }

    /// Returns `self` + `rhs` modulo [`F::MODULUS`].
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut sum = Self(self.0.add(&rhs.0), PhantomData);
        // SAFETY: `sub_assign` computes correct results even if `rhs` is `F::MODULUS`.
        unsafe { sum.sub_assign(&Self::new_unchecked(F::MODULUS)) };
        sum
    }

    /// Returns `self` - `rhs` modulo [`F::MODULUS`].
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn sub(&self, rhs: &Self) -> Self {
        let (difference, mask) = self.0.overflowing_sub(&rhs.0);
        // SAFETY: we we guarantee that underflow doesn't occur by adding the modulus back if it
        // does.
        unsafe { Self::new_unchecked(difference.add(&(F::MODULUS.and_bool(mask)))) }
    }

    /// Calculates `self` - `rhs` modulo [`F::MODULUS`], storing the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn sub_assign(&mut self, rhs: &Self) {
        let mask = self.0.overflowing_sub_assign(&rhs.0);
        // make sure self < MODULUS
        self.0.add_assign(&(F::MODULUS.and_bool(mask)));
    }

    /// Returns `self` * `rhs` modulo [`F::MODULUS`].
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn mul(&self, rhs: &Self) -> Self {
        let product = (((self.0.widening_mul(&rhs.0)).div(&F::MODULUS.into())).1).0[..4]
            .try_into()
            .unwrap();

        unsafe { Self::new_unchecked(product) }
    }

    /// Returns `self` / `rhs` modulo [`F::MODULUS`].
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn div(&self, rhs: &Self) -> Self {
        self.mul(&rhs.inverse())
    }

    pub fn sqr(&self) -> Self {
        todo!();
    }

    /// Calculates the additive inverse of `self` returning the result.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`F::ZERO`].
    pub fn neg(&self) -> Self {
        Self::sub(&F::ZERO, self)
    }

    /// Calculates the additive inverse of `self` storing the result in `self`.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`F::ZERO`].
    pub fn neg_assign(&mut self) {
        // TODO: can this be made more efficient?
        *self = Self::neg(self);
    }
}

impl<M: FiniteField> TryFrom<UBigInt<4>> for FieldElement<M> {
    type Error = InputTooLargeError;
    fn try_from(value: UBigInt<4>) -> Result<Self, Self::Error> {
        FieldElement::try_new(value)
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::big_int::UBigInt;

    use super::FieldElement;
    use crate::elliptic_curve::secp256r1::Secp256r1;
    use crate::finite_field::FiniteField;

    #[test]
    fn inverse() {
        let a = FieldElement::<Secp256r1>(
            UBigInt::from([
                0x0123456789abcdef,
                0xfedcba9876543210,
                0x0123456789abcdef,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        let inverse = FieldElement(
            UBigInt::from([
                0x26df004c195c1bad,
                0xba2f345d14469232,
                0xf1fc3784a656a487,
                0x6f8924011bb0d776,
            ]),
            PhantomData,
        );
        assert_eq!(a.inverse(), inverse);
    }

    #[test]
    fn mul() {
        let a = FieldElement::<Secp256r1>(
            UBigInt::from([
                0x0123456789abcdef,
                0xfedcba9876543210,
                0x0123456789abcdef,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        let inverse = FieldElement(
            UBigInt::from([
                0x26df004c195c1bad,
                0xba2f345d14469232,
                0xf1fc3784a656a487,
                0x6f8924011bb0d776,
            ]),
            PhantomData,
        );
        assert_eq!(a.mul(&inverse), Secp256r1::ONE);
    }
}
