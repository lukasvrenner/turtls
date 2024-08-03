use crate::big_int::{BigInt, InputTooLargeError, UBigInt};

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
pub struct FieldElement(UBigInt<4>);

impl FieldElement {
    pub const MODULUS: Self = Self(UBigInt::new([
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
    ]));

    pub const ZERO: Self = Self(UBigInt::ZERO);

    pub const MIN: Self = Self(UBigInt::MIN);

    pub const MAX: Self = Self::MODULUS;

    pub const ONE: Self = Self(UBigInt::ONE);

    /// Returns the multiplicative inverse of `self`.
    ///
    /// This value has the property that `self.inverse() * self == 1`
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn inverse(&self) -> Self {
        let mut t = BigInt::ZERO;
        let mut new_t = BigInt::ONE;
        let mut r: BigInt<4> = Self::MODULUS.0.into();
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
            t.add_assign(&Self::MODULUS.0.into())
        }
        debug_assert!(t.is_positive());
        Self(t.digits)
    }

    /// Returns the number of digits in `self`, not counting leading zeros
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn count_digits(&self) -> usize {
        self.0.count_digits()
    }

    /// Returns `self` + `rhs` modulo [`MODULUS`](Self::MODULUS)
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn add(&self, rhs: &Self) -> Self {
        Self(self.0.add(&rhs.0)).sub(&Self::MODULUS)
    }

    /// Returns `self` - `rhs` modulo [`MODULUS`](Self::MODULUS)
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn sub(&self, rhs: &Self) -> Self {
        let (difference, mask) = self.0.overflowing_sub(&rhs.0);
        Self(difference.add(&(Self::MODULUS.0.and_bool(mask))))
    }

    pub fn sub_assign(&mut self, rhs: &Self) {
        let mask = self.0.overflowing_sub_assign(&rhs.0);
        // make sure self < MODULUS
        self.0.add_assign(&(Self::MODULUS.0.and_bool(mask)));
    }

    /// Returns `self` * `rhs` mod [`MODULUS`](Self::MODULUS)
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(
            (((self.0.widening_mul(&rhs.0)).div(&Self::MODULUS.0.into())).1).0[..4]
                .try_into()
                .unwrap(),
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
        Self(value.div(&Self::MODULUS.0).1)
    }

    /// Calculates the additive inverse of `self` returning the result.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`Self::ZERO`].
    pub fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Calculates the additive inverse of `self` storing the result in `self`.
    ///
    /// The returned value has the property that, when added to `self`, the sum is [`Self::ZERO`].
    pub fn neg_assign(&mut self) {
        // TODO: can this be made more efficient?
        *self = self.neg();
    }
}

impl TryFrom<UBigInt<4>> for FieldElement {
    type Error = InputTooLargeError;
    fn try_from(value: UBigInt<4>) -> Result<Self, Self::Error> {
        if value >= Self::MODULUS.0 {
            return Err(InputTooLargeError);
        };
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Point(pub FieldElement, pub FieldElement);

impl Point {
    /// The base point
    pub const G: Point = Point(
        FieldElement(UBigInt::new([
            0xf4a13945d898c296,
            0x77037d812deb33a0,
            0xf8bce6e563a440f2,
            0x6b17d1f2e12c4247,
        ])),
        FieldElement(UBigInt::new([
            0xcbb6406837bf51f5,
            0x2bce33576b315ece,
            0x8ee7eb4a7c0f9e16,
            0x4fe342e2fe1a7f9b,
        ])),
    );
    /// Multiplies a [`Point`] by a [`FieldElement`]
    pub fn mul_scalar(&self, scalar: FieldElement) -> Self {
        let mut r0 = *self;
        let mut r1 = self.double();
        for i in (0..scalar.0.len() - 2).rev() {
            if scalar.0.0[i] == 0 {
                r1.add_assign(&r0);
                r0.double_assign();
            } else {
                r0.add_assign(&r1);
                r1.double_assign();
            }
        }
        r0
    }

    pub fn double(&self) -> Self {
        todo!();
    }

    pub fn double_assign(&mut self) {
        todo!();
    }

    /// Adds `self` and `rhs`, returning the result.
    ///
    /// # Panics:
    /// This function will panic if `self.0 == rhs.0`. That is, when they have the same
    /// x-coordinate.
    pub fn add(&self, rhs: &Self) -> Self {
        // TODO: use `assign` variants to avoid extra duplications
        let lambda = rhs.1.sub(&self.1).div(&rhs.0.sub(&self.0));
        let x = lambda.sqr().sub(&self.0).sub(&rhs.0);
        let y = lambda.mul(&self.0.sub(&rhs.0)).sub(&self.1);
        Self(x, y)
    }

    pub fn add_assign(&mut self, rhs: &Self) {
        todo!();
    }

    pub fn neg(&self) -> Self {
        let mut buf = *self;
        buf.neg_assign();
        buf
    }

    pub fn neg_assign(&mut self) {
        self.1.neg_assign();
    }

}

#[cfg(test)]
mod tests {
    use crate::big_int::UBigInt;

    use super::FieldElement;

    #[test]
    fn inverse() {
        let a = FieldElement(UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]));
        let inverse = FieldElement(UBigInt::from([
            0x26df004c195c1bad,
            0xba2f345d14469232,
            0xf1fc3784a656a487,
            0x6f8924011bb0d776,
        ]));
        assert_eq!(a.inverse(), inverse);
    }

    #[test]
    fn mul() {
        let a = FieldElement(UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]));
        let inverse = FieldElement(UBigInt::from([
            0x26df004c195c1bad,
            0xba2f345d14469232,
            0xf1fc3784a656a487,
            0x6f8924011bb0d776,
        ]));
        assert_eq!(a.mul(&inverse), FieldElement::ONE);
    }
}
