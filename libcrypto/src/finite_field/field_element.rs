use core::marker::PhantomData;

use crate::big_int::{BigInt, InputTooLargeError, UBigInt};

use super::FiniteField;
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
/// A big integer with the invariant that its value is less than its modulus
pub struct FieldElement<F: FiniteField>(pub(crate) UBigInt<4>, pub(crate) PhantomData<F>);

impl<F: FiniteField> FieldElement<F> {
    //pub const MODULUS: Self = Self(UBigInt::new([
    //    0xf3b9cac2fc632551,
    //    0xbce6faada7179e84,
    //    0xffffffffffffffff,
    //    0xffffffff00000000,
    //]));

    /// Returns the multiplicative inverse of `self`.
    ///
    /// This value has the property that `self.inverse() * self == 1`
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn inverse(&self) -> Self {
        let mut t = BigInt::ZERO;
        let mut new_t = BigInt::ONE;
        let mut r: BigInt<4> = F::MODULUS.0.into();
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
            t.add_assign(&F::MODULUS.0.into())
        }
        debug_assert!(t.is_positive());
        Self(t.digits, PhantomData)
    }

    /// Returns the number of digits in `self`, not counting leading zeros
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn count_digits(&self) -> usize {
        self.0.count_digits()
    }

    /// Returns `self` + `rhs` modulo [`MODULUS`](M::MODULUS)
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn add(&self, rhs: &Self) -> Self {
        let mut sum = Self(self.0.add(&rhs.0), PhantomData);
        sum.sub_assign(&F::MODULUS);
        sum
    }

    /// Returns `self` - `rhs` modulo [`MODULUS`](M::MODULUS)
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn sub(&self, rhs: &Self) -> Self {
        let (difference, mask) = self.0.overflowing_sub(&rhs.0);
        Self(difference.add(&(F::MODULUS.0.and_bool(mask))), PhantomData)
    }

    pub fn sub_assign(&mut self, rhs: &Self) {
        let mask = self.0.overflowing_sub_assign(&rhs.0);
        // make sure self < MODULUS
        self.0.add_assign(&(F::MODULUS.0.and_bool(mask)));
    }

    /// Returns `self` * `rhs` mod [`MODULUS`](M::MODULUS)
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(
            (((self.0.widening_mul(&rhs.0)).div(&F::MODULUS.0.into())).1).0[..4]
                .try_into()
                .unwrap(),
            PhantomData,
        )
    }

    /// Returns (`self` / `rhs`, `self` mod `rhs)`
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn div(&self, rhs: &Self) -> Self {
        self.mul(&rhs.inverse())
    }

    pub fn sqr(&self) -> Self {
        todo!();
    }

    /// Converts `value` into the equivalent [`FieldElement`].
    ///
    /// This is used instead of [`From<UBigInt<4>>`] because then we can't have a custom [`TryFrom`] implementation.
    pub fn from_u_big_int(value: UBigInt<4>) -> Self {
        Self(value.div(&F::MODULUS.0).1, PhantomData)
    }

    /// Calculates the additive inverse of `self` returning the result.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`M::ZERO`].
    pub fn neg(&self) -> Self {
        Self::sub(&F::ZERO, self)
    }

    /// Calculates the additive inverse of `self` storing the result in `self`.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`M::ZERO`].
    pub fn neg_assign(&mut self) {
        // TODO: can this be made more efficient?
        *self = Self::neg(self);
    }
}

impl<M: FiniteField> TryFrom<UBigInt<4>> for FieldElement<M> {
    type Error = InputTooLargeError;
    fn try_from(value: UBigInt<4>) -> Result<Self, Self::Error> {
        if value >= M::MODULUS.0 {
            return Err(InputTooLargeError);
        };
        Ok(Self(value, PhantomData))
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
        let a = FieldElement::<Secp256r1>(UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]), PhantomData);
        let inverse = FieldElement(UBigInt::from([
            0x26df004c195c1bad,
            0xba2f345d14469232,
            0xf1fc3784a656a487,
            0x6f8924011bb0d776,
        ]), PhantomData);
        assert_eq!(a.inverse(), inverse);
    }

    #[test]
    fn mul() {
        let a = FieldElement::<Secp256r1>(UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]), PhantomData);
        let inverse = FieldElement(UBigInt::from([
            0x26df004c195c1bad,
            0xba2f345d14469232,
            0xf1fc3784a656a487,
            0x6f8924011bb0d776,
        ]), PhantomData);
        assert_eq!(a.mul(&inverse), Secp256r1::ONE);
    }
}
