use crate::finite_field::FieldElement;

use super::{super::EllipticCurve, AffineInfinity, ProjectivePoint};
/// A point on an elliptic curve in affine representation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AffinePoint<C: EllipticCurve> {
    x: FieldElement<C>,
    y: FieldElement<C>,
}

impl<C: EllipticCurve> core::fmt::Display for AffinePoint<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("(")?;
        core::fmt::Display::fmt(&self.x, f)?;

        f.write_str(", ")?;
        core::fmt::Display::fmt(&self.y, f)?;
        f.write_str(")")?;
        Ok(())
    }
}

impl<C: EllipticCurve> core::fmt::Debug for AffinePoint<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(concat!(stringify!(AffinePoint), " { x: "))?;
        core::fmt::Debug::fmt(&self.x, f)?;

        f.write_str(", y: ")?;
        core::fmt::Debug::fmt(&self.y, f)?;
        f.write_str(" }")?;
        Ok(())
    }
}

impl<C: EllipticCurve> AffinePoint<C> {
    /// Returns the x-value of `self`.
    pub fn x(&self) -> &FieldElement<C> {
        &self.x
    }

    /// Returns the y-value of `self`.
    pub fn y(&self) -> &FieldElement<C> {
        &self.y
    }

    /// Converts `self` into its projective representation.
    pub const fn as_projective(self) -> ProjectivePoint<C> {
        // TODO: is there a better way to do this?

        // # SAFETY: The projective value is still on the curve.
        unsafe { ProjectivePoint::new_unchecked(self.x, self.y, FieldElement::ONE) }
    }

    /// Creates a new [`Point`] without verifying that it is on the curve specified b `P`.
    ///
    /// # Safety
    /// The point must be on the curve. If the point isn't on the curve, it will result in
    /// undefined behavior.
    pub const unsafe fn new_unchecked(x: FieldElement<C>, y: FieldElement<C>) -> Self {
        Self { x, y }
    }
    pub fn add(&self, rhs: &Self) -> Self {
        let y_diff = rhs.y.sub(&self.y);
        let x_diff = rhs.x.sub(&self.x);
        let slope = y_diff.div(&x_diff);
        let mut x = slope.sqr();
        x.sub_assign(&self.x);
        x.sub_assign(&rhs.x);

        let mut y = slope.mul(&self.x.sub(&x));
        y.sub_assign(&self.y);
        Self { x, y }
    }

    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
        }
    }

    pub fn neg_assign(&mut self) {
        self.y.neg_assign();
    }

    pub fn double(&self) -> Self {
        todo!();
    }

    pub fn double_assign(&mut self) {
        todo!();
    }
}

impl<C: EllipticCurve> TryFrom<ProjectivePoint<C>> for AffinePoint<C> {
    type Error = AffineInfinity;
    fn try_from(value: ProjectivePoint<C>) -> Result<AffinePoint<C>, Self::Error> {
        value.as_affine().ok_or(AffineInfinity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::big_int::UBigInt;
    use crate::elliptic_curve::Secp256r1;

    #[test]
    fn add() {
        let x = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0xa60b48fc47669978,
                0xc08969e277f21b35,
                0x8a52380304b51ac3,
                0x7cf27b188d034f7e,
            ]))
        };
        let y = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x9e04b79d227873d1,
                0xba7dade63ce98229,
                0x293d9ac69f7430db,
                0x07775510db8ed040,
            ]))
        };
        let k_2 = unsafe { AffinePoint::new_unchecked(x, y) };

        //let sum = k_2.add(&Secp256r1::BASE_POINT);
        let also_sum = Secp256r1::BASE_POINT.add(&k_2);

        let x = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0xfb41661bc6e7fd6c,
                0xe6c6b721efada985,
                0xc8f7ef951d4bf165,
                0x5ecbe4d1a6330a44,
            ]))
        };
        let y = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x9a79b127a27d5032,
                0xd82ab036384fb83d,
                0x374b06ce1a64a2ec,
                0x8734640c4998ff7e,
            ]))
        };
        let k_3 = unsafe { AffinePoint::new_unchecked(x, y) };
        assert_eq!(also_sum, k_3);
        //assert_eq!(sum, k_3);
    }
}
