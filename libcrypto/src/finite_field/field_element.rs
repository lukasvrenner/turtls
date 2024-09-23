use core::marker::PhantomData;

use crate::big_int::{BigInt, InputTooLargeError, UBigInt};

use super::FiniteField;
/// An element of the finite field `F`.
///
/// All operations are performed modulo [`F::MODULUS`](super::FiniteField::MODULUS).
#[derive(Debug, Eq, PartialOrd, Ord, PartialEq)]
pub struct FieldElement<F: FiniteField>(UBigInt<4>, PhantomData<F>);

impl<T: FiniteField> Clone for FieldElement<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: FiniteField> Copy for FieldElement<T> {}

impl<F: FiniteField> FieldElement<F> {

    // SAFETY: `FiniteField` implementors guarantee that `ZERO` is in the field.
    pub const ZERO: Self = unsafe { Self::new_unchecked(UBigInt::ZERO) };

    // SAFETY: `FiniteField` implementors guarantee that `ONE` is in the field.
    pub const ONE: Self = unsafe { Self::new_unchecked(UBigInt::ONE) };
    /// Creates a new `FieldElement` from `value`.
    ///
    /// If `value` is greater than [`F::MODULUS`](super::FiniteField::MODULUS), it is properly reduced.
    ///
    /// Because it always performs a division operation, this function is much slower than a simple
    /// type conversion. If higher performance, at the cost of falibility, is necessary, use
    /// [`Self::try_new()`] or its unsafe counterpart, [`Self::new_unchecked()`]
    pub fn new(value: UBigInt<4>) -> Self {
        Self(value.div(&F::MODULUS).1, PhantomData)
    }

    /// Creates a new [`FieldElement`] without checking if `int` is less than [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// # Safety
    /// `int` must be less than [`F::MODULUS`](super::FiniteField::MODULUS). A violation of this will result in undefined
    /// behavior.
    ///
    /// In most cases, it's better to use the safe version: [`Self::try_new()`]
    pub const unsafe fn new_unchecked(int: UBigInt<4>) -> Self {
        Self(int, PhantomData)
    }

    /// Creates a new [`FieldElement`] from `int`, returning an [`Err`] if `int`
    /// is greater than or equal to [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// This is the safe version of [`Self::new_unchecked()`]
    pub fn try_new(int: UBigInt<4>) -> Result<Self, InputTooLargeError> {
        if int >= F::MODULUS {
            return Err(InputTooLargeError);
        };
        // SAFETY: we already checked to guarantee that `int` is less than `F::MODULUS`.
        Ok(unsafe { Self::new_unchecked(int) })
    }

    pub fn inner(&self) -> &UBigInt<4> {
        &self.0
    }

    pub fn into_inner(self) -> UBigInt<4> {
        self.0
    }

    /// Returns the modular multiplicative inverse of `self`.
    ///
    /// This value has the property that `self.inverse() * self == 1`
    ///
    /// # Constant-timedness
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
                t.sub(&quotient.widening_mul(&new_t).resize()),
            );
            (r, new_r) = (new_r, remainder);
        }
        debug_assert_eq!(r, BigInt::ONE);
        // TODO: is it better to use a mask for branchlessness?
        if t.is_negative() {
            t.add_assign(&F::MODULUS.into())
        }
        debug_assert!(t.is_positive());
        debug_assert!(t.digits < F::MODULUS);
        // TODO: is it better to use safe or unsafe version?
        unsafe { Self::new_unchecked(t.digits) }
    }

    /// Returns the number of digits in `self`, not counting leading zeros
    ///
    /// # Constant-timedness
    /// This function is constant-time.
    pub fn count_digits(&self) -> usize {
        self.0.count_digits()
    }

    /// Returns `self + rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut sum;
        // SAFETY: adding a value less than `F::MODULUS` and then performing modular subtraction of
        // `F::MODULUS` will always be inside the appropriate range.
        unsafe {
            sum = Self::new_unchecked(self.0.add(&rhs.0));
            sum.sub_assign(&Self::new_unchecked(F::MODULUS))
        };
        sum
    }

    pub fn double(&self) -> Self {
        self.add(self)
    }

    pub fn double_assign(&mut self) {
        todo!();
    }

    /// Returns `self - rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn sub(&self, rhs: &Self) -> Self {
        let (difference, mask) = self.0.overflowing_sub(&rhs.0);
        // SAFETY: we we guarantee that underflow doesn't occur by adding the modulus back if it
        // does.
        unsafe { Self::new_unchecked(difference.add(&(F::MODULUS.and_bool(mask)))) }
    }

    /// Sets self to `self - rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn sub_assign(&mut self, rhs: &Self) {
        let mask = self.0.overflowing_sub_assign(&rhs.0);
        // make sure self < MODULUS
        self.0.add_assign(&(F::MODULUS.and_bool(mask)));
    }

    /// Returns `self * rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// # Constant-timedness
    /// TODO: document constant-timedness
    pub fn mul(&self, rhs: &Self) -> Self {
        // TODO: use barret reduction instead of division.
        let product = self.0.widening_mul(&rhs.0).div(&F::MODULUS.resize()).1.resize();
        unsafe { Self::new_unchecked(product) }
    }

    /// Sets `self` to `self * rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    pub fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul(rhs);
    }

    /// Returns `self / rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    ///
    /// # Constant-timedness
    /// TODO: document constant-timedness
    pub fn div(&self, rhs: &Self) -> Self {
        self.mul(&rhs.inverse())
    }

    /// Returns the square of `self` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    pub fn sqr(&self) -> Self {
        self.mul(self)
    }

    /// Squares `self` module [`F::MODULUS`](super::FiniteField::MODULUS) and stores the result of `self`.
    pub fn sqr_assign(&mut self) {
        *self = self.sqr();
    }

    /// Returns the modular additive inverse of `self`.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`F::ZERO`](super::FiniteField::ZERO).
    pub fn neg(&self) -> Self {
        Self::sub(&Self::ZERO, self)
    }

    /// Sets `self` to the modular additive inverse of `self`.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`F::ZERO`](super::FiniteField::ZERO).
    pub fn neg_assign(&mut self) {
        // TODO: can this be made more efficient?
        *self = self.neg();
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
    use crate::elliptic_curve::Secp256r1;

    #[test]
    fn inverse() {
        let a = FieldElement::<Secp256r1>(
            UBigInt([
                0x0123456789abcdef,
                0xfedcba9876543210,
                0x0123456789abcdef,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        let inverse = FieldElement(
            UBigInt([
                0x5d97c948e23c79c0,
                0x89c9a8bb5116b562,
                0xec57bfa67717cf1b,
                0x840b25e463c7037A,
            ]),
            PhantomData,
        );
        assert_eq!(a.inverse(), inverse);
        assert_eq!(FieldElement::<Secp256r1>::ONE.inverse(), FieldElement::ONE);
        let a = FieldElement::<Secp256r1>(
            UBigInt([
                0x1001039120910903,
                0x12012ae213030aef,
                0x0,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        let inverse = FieldElement(
            UBigInt([
                0xaaa905c8ae9acf5c,
                0x11b236a5fb747f65,
                0x6dcf21026cf56b29,
                0x75713d3a63705199,
            ]),
            PhantomData,
        );
        assert_eq!(inverse.mul(&a), FieldElement::ONE);
    }

    #[test]
    fn mul() {
        let a = FieldElement::<Secp256r1>(
            UBigInt([
                0x0123456789abcdef,
                0xfedcba9876543210,
                0x0123456789abcdef,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        let inverse = FieldElement(
            UBigInt([
                0x5d97c948e23c79c0,
                0x89c9a8bb5116b562,
                0xec57bfa67717cf1b,
                0x840b25e463c7037A,
            ]),
            PhantomData,
        );
        assert_eq!(a.mul(&inverse), FieldElement::ONE);

        let inverse = FieldElement(
            UBigInt([
                0xaaa905c8ae9acf5c,
                0x11b236a5fb747f65,
                0x6dcf21026cf56b29,
                0x75713d3a63705199,
            ]),
            PhantomData,
        );
        let a = FieldElement::<Secp256r1>(
            UBigInt([
                0x1001039120910903,
                0x12012ae213030aef,
                0x0,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        assert_eq!(a.mul(&inverse), FieldElement::ONE);
    }
}
