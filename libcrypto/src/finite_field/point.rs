use core::marker::PhantomData;

use super::{FieldElement, FiniteField};
use crate::big_int::UBigInt;
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub struct Point<F: FiniteField>(pub FieldElement<F>, pub FieldElement<F>);

impl<F: FiniteField> Point<F> {
    /// The base point
    // SAFETY: both points are less than ``
    //pub const G: Point<F> = unsafe {Point(
    //    FieldElement::new_unchecked(
    //        UBigInt::new([
    //            0xf4a13945d898c296,
    //            0x77037d812deb33a0,
    //            0xf8bce6e563a440f2,
    //            0x6b17d1f2e12c4247,
    //        ]),
    //    ),
    //    FieldElement::new_unchecked(
    //        UBigInt::new([
    //            0xcbb6406837bf51f5,
    //            0x2bce33576b315ece,
    //            0x8ee7eb4a7c0f9e16,
    //            0x4fe342e2fe1a7f9b,
    //        ]),
    //    ),
    //)};
    pub const G: Point<F> = todo!();

    /// Multiplies a [`Point`] by a [`FieldElement`]
    pub fn mul_scalar(&self, scalar: FieldElement<F>) -> Self {
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
