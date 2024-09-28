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
    /// The point at infinity.
    ///
    /// Note: this is not necessarily the same as `self.is_infinity()`
    pub const POINT_AT_INF: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Returns `true` if `self` is the point at infinity and `false` otherwise.
    ///
    /// Note: this is not necessarily the same as `self == POINT_AT_INF`.
    pub fn is_infinity(&self) -> bool {
        self.z == FieldElement::ZERO
    }

    /// Converts `self` into its affine representation.
    pub fn as_affine(self) -> Option<AffinePoint<C>> {
        if self.is_infinity() {
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

    /// Creates a new [`ProjectivePoint`] along the curve.
    /// # Safety
    /// The point must be on the curve.
    pub const unsafe fn new_unchecked(
        x: FieldElement<C>,
        y: FieldElement<C>,
        z: FieldElement<C>,
    ) -> Self {
        Self { x, y, z }
    }

    /// Adds `self` and `rhs`, returning the other point if either point is infinity.
    ///
    /// Generally, use this method instead of [`add_fast`]. If, however, it is guaranteed that neither
    /// point is infinity, consider using [`add_fast`].
    ///
    /// [`add_fast`]: ProjectivePoint::add_fast
    pub fn add(&self, rhs: &Self) -> Self {
        if self.is_infinity() {
            return *rhs;
        }
        if rhs.is_infinity() {
            return *self;
        }
        Self::add_fast(self, rhs)
    }

    /// Adds `self` and `rhs`, returning [`POINT_AT_INF`] if either point is infinity.
    ///
    /// Generally, use [`add`] instead of this method. If, however, it is guaranteed that neither
    /// point is infinity, consider using this method.
    ///
    /// [`add`]: ProjectivePoint::add
    /// [`POINT_AT_INF`]: ProjectivePoint::POINT_AT_INF
    pub fn add_fast(&self, rhs: &Self) -> Self {
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

        let w = self.z.mul(&rhs.z);

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


    pub fn add_assign_fast(&mut self, rhs: &Self) {
        // SAFETY: the caller guarantees that neither point is POINT_AT_INF.
        *self = self.add_fast(rhs);
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
            unsafe { self.double_assign() }
            return;
        }
        self.add_assign_fast(rhs);
    }

    pub fn double(&self) -> Self {
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
        *self = self.double()
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
    use super::EllipticCurve;
    use crate::big_int::UBigInt;
    use crate::elliptic_curve::{AffinePoint, ProjectivePoint, Secp256r1};
    use crate::finite_field::FieldElement;

    // test values from http://point-at-infinity.org/ecc/nisttv

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
        // Secp256r1::BASE_POINT * 2
        let k_2 = unsafe { AffinePoint::new_unchecked(x, y) }.as_projective();

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
        // Secp256r1::BASE_POINT * 3
        let k_3 = unsafe { AffinePoint::new_unchecked(x, y) };

        let sum = k_2.add(&Secp256r1::BASE_POINT.as_projective()).as_affine();
        assert_eq!(sum, Some(k_3));

        let also_sum = Secp256r1::BASE_POINT.as_projective().add(&k_2).as_affine();
        assert_eq!(also_sum, Some(k_3));
    }

    #[test]
    fn add_fast() {
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
        // Secp256r1::BASE_POINT * 2
        let k_2 = unsafe { AffinePoint::new_unchecked(x, y) }.as_projective();

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
        // Secp256r1::BASE_POINT * 3
        let k_3 = unsafe { AffinePoint::new_unchecked(x, y) };

        let sum = k_2
            .add_fast(&Secp256r1::BASE_POINT.as_projective())
            .as_affine();
        assert_eq!(sum, Some(k_3));

        let inf = Secp256r1::BASE_POINT
            .as_projective()
            .add_fast(&ProjectivePoint::POINT_AT_INF)
            .as_affine();
        assert_eq!(inf, None);

        let inf = k_3.as_projective().neg().add_fast(&k_3.as_projective()).as_affine();
        assert_eq!(inf, None);

    }

    #[test]
    fn double() {
        let point = Secp256r1::BASE_POINT.as_projective().double().as_affine();
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
        assert_eq!(point, Some(sum));
    }

    #[test]
    fn mul_scalar() {
        let point = Secp256r1::BASE_POINT
            .as_projective()
            .mul_scalar(UBigInt::ONE)
            .as_affine();

        assert_eq!(point, Some(Secp256r1::BASE_POINT));

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
            .as_affine();

        assert_eq!(point, Some(product))
    }
}
