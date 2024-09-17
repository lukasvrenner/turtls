use crate::finite_field::FieldElement;

use super::EllipticCurve;
/// A point on an elliptic curve.
#[derive(Clone, Debug, Copy, Eq)]
pub struct Point<F: EllipticCurve> {
    x: FieldElement<F>,
    y: FieldElement<F>,
}

impl<F: EllipticCurve> PartialEq for Point<F> {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl<F: EllipticCurve> Point<F> {
    pub fn x(&self) -> &FieldElement<F> {
        &self.x
    }

    pub fn y(&self) -> &FieldElement<F> {
        &self.y
    }

    /// Creates a new [`Point`] without verifying that it is on the curve specified b `P`.
    ///
    /// # Safety
    /// The point must be on the curve. If the point isn't on the curve, it will result in
    /// undefined behavior.
    pub const unsafe fn new_unchecked(x: FieldElement<F>, y: FieldElement<F>) -> Self {
        Self { x, y }
    }
    /// Multiplies a [`Point`] by a [`FieldElement`]
    pub fn mul_scalar(&self, scalar: FieldElement<F>) -> Self {
        todo!()
    }

    /// Adds `self` and `rhs`, returning the result.
    pub fn add(&self, rhs: &Self) -> Self {
        // TODO: use `assign` variants to avoid extra duplications
        let lambda = rhs.y.sub(&self.y).div(&rhs.x.sub(&self.x));
        let x = lambda.sqr().sub(&self.x).sub(&rhs.x);
        let y = lambda.mul(&self.x.sub(&rhs.x)).sub(&self.y);
        Self { x, y }
    }

    pub fn add_assign(&mut self, rhs: &Self) {
        *self = self.add(rhs);
    }

    pub fn double(&self) -> Self {
        todo!()
    }

    pub fn double_assign(&mut self) {
        *self = self.double();
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
}
