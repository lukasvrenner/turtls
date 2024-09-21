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
    pub const unsafe fn new_unsafe(
        x: FieldElement<C>,
        y: FieldElement<C>,
        z: FieldElement<C>,
    ) -> Self {
        Self { x, y, z }
    }
}

impl<C: EllipticCurve> Point for ProjectivePoint<C> {
    fn add(&self, rhs: &Self) -> Self {
        todo!()
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
