use super::{super::EllipticCurve, AffinePoint, Point};
use crate::finite_field::FieldElement;

/// A point on [`EllipticCurve`] `C` in projective representation.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct ProjectivePoint<C: EllipticCurve> {
    x: FieldElement<C>,
    y: FieldElement<C>,
    z: FieldElement<C>,
}

impl<C: EllipticCurve> ProjectivePoint<C> {
    /// Converts `self` into its affine representation.
    pub fn as_affine(self) -> AffinePoint<C> {
        let z_inv = self.z.inverse();

        unsafe { AffinePoint::new_unchecked(self.x.mul(&z_inv), self.y.mul(&z_inv)) }
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
}

impl<C: EllipticCurve> Point for ProjectivePoint<C> {
    fn add(&self, rhs: &Self) -> Self {
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

    fn double(&self) -> Self {
        todo!()
    }

    fn neg(&self) -> Self {
        todo!()
    }
}

impl<C: EllipticCurve> From<AffinePoint<C>> for ProjectivePoint<C> {
    fn from(value: AffinePoint<C>) -> Self {
        value.as_projective()
    }
}
