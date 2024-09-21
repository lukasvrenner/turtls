use super::{AffinePoint, EllipticCurve};
use crate::finite_field::FieldElement;

/// A point on [`EllipticCurve`] `C` in projective representation.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct ProjectivePoint<C: EllipticCurve> {
    pub(super) x: FieldElement<C>,
    pub(super) y: FieldElement<C>,
    pub(super) z: FieldElement<C>,
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

impl<C: EllipticCurve> From<AffinePoint<C>> for ProjectivePoint<C> {
    fn from(value: AffinePoint<C>) -> Self {
        value.as_projective()
    }
}
