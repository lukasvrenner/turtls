use core::marker::PhantomData;

use crate::big_int::{BigInt, InputTooLargeError, UBigInt};

use super::FiniteField;
/// An element of the finite field `F`.
///
/// All operations are performed modulo [`F::MODULUS`](super::FiniteField::MODULUS).
#[derive(Eq, PartialOrd, Ord, PartialEq, Clone, Copy)]
pub struct FieldElement<F: FiniteField>(UBigInt<4>, PhantomData<F>);

impl<F: FiniteField> core::fmt::Display for FieldElement<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl<F: FiniteField> core::fmt::Debug for FieldElement<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self.0, f)
    }
}

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
    /// # Panics
    /// This function panics if `self` is `FieldElement::ZERO` in debug mode.
    ///
    /// In release mode, `FieldElement::ZERO.inverse()` returns `FieldElement::ZERO`.
    /// # Constant-timedness
    /// TODO: document constant-timedness
    pub fn inverse(&self) -> Self {
        debug_assert_ne!(self, &Self::ZERO);
        debug_assert!(self.0 < F::MODULUS);
        let mut t = BigInt::ZERO;
        let mut new_t = BigInt::ONE;
        let mut r: BigInt<4> = F::MODULUS.into();
        let mut new_r: BigInt<4> = self.0.into();

        while new_r != BigInt::ZERO {
            let (quotient, remainder) = r.div(&new_r);
            (t, new_t) = (new_t, t.sub(&quotient.widening_mul(&new_t).resize()));
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

    pub fn add_assign(&mut self, rhs: &Self) {
        unsafe {
            self.0.add_assign(&rhs.0);
            self.sub_assign(&Self::new_unchecked(F::MODULUS));
        }
    }

    pub fn double(&self) -> Self {
        self.add(self)
    }

    pub fn double_assign(&mut self) {
        unsafe {
            self.0.double_assign();
            self.sub_assign(&Self::new_unchecked(F::MODULUS));
        }
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
        let product = self
            .0
            .widening_mul(&rhs.0)
            .div(&F::MODULUS.resize())
            .1
            .resize();
        //debug_assert!(product < F::MODULUS)
        unsafe { Self::new_unchecked(product) }
    }

    /// Sets `self` to `self * rhs` modulo [`F::MODULUS`](super::FiniteField::MODULUS).
    pub fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul(rhs);
    }

    pub fn mul_digit_assign(&mut self, digit: u64) {
        let mut carry = 0;
        for i in 0..self.0.len() {
            (self.0.0[i], carry) = crate::big_int::carry_mul(self.0.0[i], digit, carry);
        }
        self.0.div_assign(&F::MODULUS);
    }

    pub fn mul_digit(&self, digit: u64) -> Self {
        let mut carry = 0;
        let mut buf = UBigInt::ZERO;
        for i in 0..self.0.len() {
            (buf.0[i], carry) = crate::big_int::carry_mul(self.0.0[i], digit, carry);
        }
        Self::new(buf)
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
        Self::ZERO.sub(self)
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
                0x0000000000000000,
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
        assert_eq!(a.inverse(), inverse);
        assert_eq!(inverse.inverse(), a);
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
                0x0000000000000000,
                0xfedcba9876543210,
            ]),
            PhantomData,
        );
        assert_eq!(a.mul(&inverse), FieldElement::ONE);
        assert_eq!(inverse.mul(&a), FieldElement::ONE);
    }

    #[test]
    fn sub() {
        let a = FieldElement(
            UBigInt([
                0xcbb6406837bf51f5,
                0x2bce33576b315ece,
                0x8ee7eb4a7c0f9e16,
                0x4fe342e2fe1a7f9b,
        ]), PhantomData,);

        let b = FieldElement::<Secp256r1>(
            UBigInt([
                0x9e04b79d227873d1,
                0xba7dade63ce98229,
                0x293d9ac69f7430db,
                0x07775510db8ed040,
            ]),
            PhantomData,
        );

        let diff = FieldElement(
            UBigInt([
                0x2db188cb1546de24,
                0x715085712e47dca5,
                0x65aa5083dc9b6d3a,
                0x486bedd2228baf5b,
        ]), PhantomData,);

        let diff_2 = FieldElement(
            UBigInt([
                0xd24e7734eab921db,
                0x8eaf7a8fd1b8235a,
                0x9a55af7c236492c5,
                0xb794122cdd7450a5,
        ]), PhantomData,);

        assert_eq!(a.sub(&b), diff);
        assert_eq!(b.sub(&a), diff_2);
    }

    #[test]
    fn neg() {
        let a = FieldElement::<Secp256r1>(
            UBigInt([
                0x2db188cb1546de24,
                0x715085712e47dca5,
                0x65aa5083dc9b6d3a,
                0x486bedd2228baf5b,
        ]), PhantomData,);

        let b = FieldElement(
            UBigInt([
                0xd24e7734eab921db,
                0x8eaf7a8fd1b8235a,
                0x9a55af7c236492c5,
                0xb794122cdd7450a5,
        ]), PhantomData,);
        assert_eq!(a.neg(), b);

        let c = FieldElement::<Secp256r1>(
            UBigInt([
                0xb16a0fb66ecdd6e2,
                0x4985ec614a06e794,
                0x9195511da110d9d1,
                0x11daa925abd70d36,
            ]),
            PhantomData,
        );

        let d = FieldElement(
            UBigInt([
                0x4e95f0499132291d,
                0xb67a139fb5f9186b,
                0x6e6aaee25eef262e,
                0xee2556d95428f2ca,
            ]),
            PhantomData,
        );

        assert_eq!(c.neg(), d);

    }

    #[test]
    fn div() {
        let a = FieldElement::<Secp256r1>(
            UBigInt([
                0xd24e7734eab921db,
                0x8eaf7a8fd1b8235a,
                0x9a55af7c236492c5,
                0xb794122cdd7450a5,
            ]),
            PhantomData,
        );

        let b = FieldElement(
            UBigInt([
                0xb16a0fb66ecdd6e2,
                0x4985ec614a06e794,
                0x9195511da110d9d1,
                0x11daa925abd70d36,
            ]),
            PhantomData,
        );

        let c = FieldElement::<Secp256r1>(
            UBigInt([
                0x2db188cb1546de24,
                0x715085712e47dca5,
                0x65aa5083dc9b6d3a,
                0x486bedd2228baf5b,
        ]), PhantomData,);

        let d = FieldElement(
            UBigInt([
                0x4e95f0499132291d,
                0xb67a139fb5f9186b,
                0x6e6aaee25eef262e,
                0xee2556d95428f2ca,
            ]),
            PhantomData,
        );

        let quotient = FieldElement(
            UBigInt([
                0x762de4ca226a8086,
                0xca4cee083742bada,
                0xc59fb73f85f16459,
                0x28cdb0fe6681d140,
            ]),
            PhantomData,
        );

        assert_eq!(a.div(&b), quotient);
        assert_eq!(c.div(&d), quotient);
    }
}
