use crate::big_int::UBigInt;

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
    pub fn inverse(self) -> Self {
        let mut y1 = UBigInt::<4>::ONE;
        let mut y2 = UBigInt::ZERO;
        let mut i = Self::MODULUS.0;
        let mut j = self.0;
        let expanded_modulus = {
            let mut expanded_modulus = UBigInt::<8>::ZERO;
            expanded_modulus[..4].copy_from_slice(&Self::MODULUS.0[..]);
            expanded_modulus
        };
        while j > UBigInt::ZERO {
            let (quotient, remainder) = i.div(&j);
            let y = y2.sub(
                &(y1.expanding_mul(&quotient).div(&expanded_modulus).1[..4]
                    .try_into()
                    .unwrap()),
            );
            i = j;
            j = remainder;
            y2 = y1;
            assert_ne!(y2, UBigInt::ZERO);
            y1 = y;
        }
        Self(UBigInt::<4>::from(<[u64; 4]>::try_from(&y2[..4]).unwrap()))
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
        let (difference, carry) = self.0.overflowing_sub(&rhs.0);
        Self(difference.add(&(Self::MODULUS.0.and_bool(carry))))
    }

    /// Returns `self` * `rhs` mod [`MODULUS`](Self::MODULUS)
    ///
    /// # Constant-timedness:
    /// This function is constant-time
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(
            (((self.0.expanding_mul(&rhs.0)).div(&Self::MODULUS.0.into())).1)[..4]
                .try_into()
                .unwrap(),
        )
        //todo!();
    }

    /// Returns (`self` / `rhs`, `self` mod `rhs)`
    ///
    /// # Constant-timedness:
    /// TODO: document constant-timedness
    pub fn div(&self, rhs: &Self) -> (Self, Self) {
        let (quotient, remainder) = self.0.div(&rhs.0);
        // guaranteed to be less than `Self::MODULUS`
        (Self(quotient), Self(remainder))
    }
}

impl From<UBigInt<4>> for FieldElement {
    fn from(value: UBigInt<4>) -> Self {
        Self((value.div(&Self::MODULUS.0)).1)
    }
}

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
        todo!();
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
        let inverse = a.inverse();
        assert_eq!(a.mul(&inverse), FieldElement::ONE);
    }
}
