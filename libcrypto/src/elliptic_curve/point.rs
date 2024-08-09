use crate::finite_field::FieldElement;

use super::EllipticCurve;
/// A point on an elliptic curve.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub struct Point<P: EllipticCurve> {
    x: FieldElement<P>,
    y: FieldElement<P>,
}

impl<P: EllipticCurve> Point<P> {

    pub fn x(&self) -> &FieldElement<P> {
        &self.x
    }

    pub fn y(&self) -> &FieldElement<P> {
        &self.y
    }

    /// Creates a new [`Point`] without verifying that it is on the curve specified b `P`.
    ///
    /// # Safety
    /// The point must be on the curve. If the point isn't on the curve, it will result in
    /// undefined behavior.
    pub const unsafe fn new_unchecked(x: FieldElement<P>, y: FieldElement<P>) -> Self {
        Self { x, y }
    }
    /// Multiplies a [`Point`] by a [`FieldElement`]
    pub fn mul_scalar(&self, scalar: FieldElement<P>) -> Self {
        todo!()
    }

    pub fn double(&self) -> Self {
        todo!();
    }

    pub fn double_assign(&mut self) {
        todo!();
    }

    /// Adds `self` and `rhs`, returning the result.
    ///
    /// # Panics
    /// This function will panic if `self.0 == rhs.0`. That is, when they have the same
    /// x-coordinate.
    pub fn add(&self, rhs: &Self) -> Self {
        // TODO: use `assign` variants to avoid extra duplications
        let lambda = rhs.y.sub(&self.y).div(&rhs.x.sub(&self.x));
        let x = lambda.sqr().sub(&self.x).sub(&rhs.x);
        let y = lambda.mul(&self.x.sub(&rhs.x)).sub(&self.y);
        Self { x, y }
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
        self.y.neg_assign();
    }
}
