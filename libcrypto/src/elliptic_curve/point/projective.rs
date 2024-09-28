use super::{super::EllipticCurve, AffinePoint};
use crate::{big_int::UBigInt, finite_field::FieldElement};

/// A point on [`EllipticCurve`] `C` in projective representation.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct ProjectivePoint<C: EllipticCurve> {
    x: FieldElement<C>,
    y: FieldElement<C>,
    z: FieldElement<C>,
}

impl<C: EllipticCurve> ProjectivePoint<C> {
    pub const POINT_AT_INF: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };
    /// Converts `self` into its affine representation.
    pub fn as_affine(self) -> Option<AffinePoint<C>> {
        // TODO: only check z coordinate?
        if self == Self::POINT_AT_INF {
            return None;
        }
        let z_inv = self.z.inverse();

        unsafe {
            Some(AffinePoint::new_unchecked(
                self.x.mul(&z_inv),
                self.y.mul(&z_inv),
            ))
        }
    }

    /// Creates a new `ProjectivePoint` along the curve.
    /// # Safety
    /// The point must be on the curve.
    pub const unsafe fn new_unchecked(
        x: FieldElement<C>,
        y: FieldElement<C>,
        z: FieldElement<C>,
    ) -> Self {
        Self { x, y, z }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        if self == &Self::POINT_AT_INF {
            return *rhs;
        }
        if rhs == &Self::POINT_AT_INF {
            return *self;
        }
        if self == &rhs.neg() {
            return Self::POINT_AT_INF;
        }

        if self == rhs {
            // SAFETY: self isn't POINT_AT_INF
            return unsafe { self.double_unchecked() };
        }
        // SAFETY: we just checked that neither point is POINT_AT_INF and that they aren't the
        // negative of eachother.
        unsafe { Self::add_unchecked(self, rhs) }
    }

    /// Adds `self` and `rhs`, assuming neither are [`ProjectivePoint::POINT_AT_INF`].
    ///
    /// # Safety:
    /// Neither `self` nor `rhs` can be [`ProjectivePoint::POINT_AT_INF`].
    /// Additionally, `rhs` cannot be `self` or the negative of `self`.
    pub unsafe fn add_unchecked(&self, rhs: &Self) -> Self {
        let u_2 = self.y.mul(&rhs.z);
        let u = {
            let mut u_1 = rhs.y.mul(&self.z);
            u_1.sub_assign(&u_2);
            u_1
        };

        let v_2 = self.x.mul(&rhs.z);
        let v = {
            let mut v_1 = rhs.x.mul(&self.z);
            v_1.sub_assign(&v_2);
            v_1
        };
        let v_sqr = v.sqr();
        let v_cube = v_sqr.mul(&v);
        // TODO: name this something better
        let v_2_v_sqr = v_sqr.mul(&v_2);

        let w = self.z.sub(&rhs.z);

        let a = {
            let mut a = u.sqr();
            a.mul_assign(&w);
            a.sub_assign(&v_cube);
            a.sub_assign(&v_2_v_sqr.double());
            a
        };
        let x = v.mul(&a);
        let y = {
            let mut y = u.mul(&v_2_v_sqr.sub(&a));
            y.sub_assign(&v_cube.mul(&u_2));
            y
        };
        let z = v_cube.mul(&w);
        unsafe { Self::new_unchecked(x, y, z) }
    }

    /// # Safety:
    /// Neither `self` nor `rhs` can be [`ProjectivePoint::POINT_AT_INF`].
    /// Additionally, `rhs` cannot be `self` or the negative of `self`.
    pub unsafe fn add_assign_unchecked(&mut self, rhs: &Self) {
        // SAFETY: the caller guarantees that neither point is POINT_AT_INF.
        *self = unsafe { self.add_unchecked(rhs) };
    }

    pub fn add_assign(&mut self, rhs: &Self) {
        if self == &Self::POINT_AT_INF {
            *self = *rhs;
            return;
        }
        if rhs == &Self::POINT_AT_INF {
            return;
        }
        if self == &rhs.neg() {
            *self = Self::POINT_AT_INF;
        }
        if self == rhs {
            // SAFETY: self isn't POINT_AT_INF
            unsafe { self.double_assign_unchecked() }
            return;
        }
        // SAFETY: we just checked that neither point is POINT_AT_INF and that they aren't the
        // negative of eachother.
        unsafe { self.add_assign_unchecked(rhs) };
    }

    pub fn double(&self) -> Self {
        if self == &Self::POINT_AT_INF {
            return Self::POINT_AT_INF;
        }
        // SAFETY: we just checked that neither point is POINT_AT_INF.
        unsafe { self.double_unchecked() }
    }

    /// # Safety:
    /// `self` cannot be [`ProjectivePoint::POINT_AT_INF`].
    pub unsafe fn double_unchecked(&self) -> Self {
        let w = {
            let mut three_x_sqr = self.x.sqr();
            three_x_sqr.mul_digit_assign(3);

            let mut w = self.z.sqr();
            w.mul_assign(&C::A);
            w.add_assign(&three_x_sqr);
            w
        };
        let s = self.y.mul(&self.z);

        // TODO: only reduce once?
        let eight_s_sqr = {
            let mut temp = s.sqr();
            temp.mul_digit_assign(8);
            temp
        };
        let b = {
            let mut b = self.x.mul(&self.y);
            b.mul_assign(&s);
            b
        };
        let h = {
            let mut h = w.sqr();
            h.sub_assign(&b.mul_digit(8));
            h
        };
        let x = {
            let mut x = h.mul(&s);
            x.double_assign();
            x
        };
        let y = {
            let mut temp = self.y.sqr();
            // TODO: only reduce once?
            temp.mul_assign(&eight_s_sqr);

            let mut y = b.mul_digit(4);
            y.sub_assign(&h);
            y.mul_assign(&w);
            y.sub_assign(&temp);
            y
        };
        let z = eight_s_sqr.mul(&s);
        Self { x, y, z }
    }

    pub fn double_assign(&mut self) {
        if self == &Self::POINT_AT_INF {
            return;
        }
        unsafe { self.double_assign_unchecked() }
    }

    /// # Safety:
    /// `self` cannot be [`ProjectivePoint::POINT_AT_INF`].
    pub unsafe fn double_assign_unchecked(&mut self) {
        *self = unsafe { self.double_unchecked() }
    }

    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    pub fn neg_assign(&mut self) {
        self.y.neg_assign();
    }

    // TODO: make an unchecked and checked version
    pub fn mul_scalar(&self, mut scalar: UBigInt<4>) -> Self {
        // TODO: can we avoid POINT_AT_INF and use add_assign_unchecked() and double_assign_unchecked()
        // by prereducing scalar until addition actually occurs? On top of minor performance
        // improvements, this would allow the return of the Point trait.
        let mut result = Self::POINT_AT_INF;
        let mut temp = *self;
        while scalar != UBigInt::ZERO {
            if scalar.0[0] & 1 == 0 {
                temp.add_assign(&result);
                result.double();
            }
            result.add_assign(&temp);
            temp.double_assign();
            scalar.shift_right_assign(1);
        }
        result
    }

    pub fn mul_scalar_assign(&mut self, scalar: UBigInt<4>) {
        *self = self.mul_scalar(scalar);
    }
}

impl<C: EllipticCurve> From<AffinePoint<C>> for ProjectivePoint<C> {
    fn from(value: AffinePoint<C>) -> Self {
        value.as_projective()
    }
}

#[cfg(test)]
mod tests {
    // test values from http://point-at-infinity.org/ecc/nisttv

    use super::EllipticCurve;
    use crate::big_int::UBigInt;
    use crate::elliptic_curve::{AffinePoint, Secp256r1};
    use crate::finite_field::FieldElement;

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
        let old_point = unsafe { AffinePoint::new_unchecked(x, y) }.as_projective();
        let point = Secp256r1::BASE_POINT
            .as_projective()
            .add(&old_point)
            .as_affine()
            .unwrap();
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
        let sum = unsafe { AffinePoint::new_unchecked(x, y) };
        assert_eq!(point, sum);
    }

    #[test]
    fn double() {
        let point = Secp256r1::BASE_POINT
            .as_projective()
            .double()
            .as_affine()
            .unwrap();
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
        let sum = unsafe { AffinePoint::new_unchecked(x, y) };
        assert_eq!(point, sum);
    }

    #[test]
    fn mul_scalar() {
        let point = Secp256r1::BASE_POINT
            .as_projective()
            .mul_scalar(UBigInt::ONE)
            .as_affine()
            .unwrap();
        assert_eq!(point, Secp256r1::BASE_POINT);
        let scalar = UBigInt::from(112233445566778899);
        let x = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x22795513aeaab82f,
                0x77dbfb3ae3d96f4c,
                0x807fe862a86be779,
                0x339150844ec15234,
            ]))
        };
        let y = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0xb1c14ddfdc8ec1b2,
                0x583f51e85a5eb3a1,
                0x55840f2034730e9b,
                0x5ada38b674336a21,
            ]))
        };
        let product = unsafe { AffinePoint::new_unchecked(x, y) };
        let point = Secp256r1::BASE_POINT
            .as_projective()
            .mul_scalar(scalar)
            .as_affine()
            .unwrap();
        assert_eq!(point, product)
    }
}
