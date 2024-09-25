pub mod affine;
pub mod projective;

pub use affine::AffinePoint;
pub use projective::ProjectivePoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AffineInfinity;

impl core::fmt::Display for AffineInfinity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the point at inifinity cannot be represented in affine coordinates")
    }
}

impl core::error::Error for AffineInfinity {}
//
///// A point on an elliptic curve.
//pub trait Point: Sized {
//    fn add(&self, rhs: &Self) -> Self;
//
//    fn add_assign(&mut self, rhs: &Self) {
//        *self = self.add(rhs);
//    }
//
//    fn double(&self) -> Self;
//
//    fn double_assign(&mut self) {
//        *self = self.double();
//    }
//
//    fn mul_scalar(&self, scalar: &UBigInt<4>) -> Self {
//        todo!();
//    }
//
//    fn mul_scalar_assign(&mut self, scalar: &UBigInt<4>) {
//        todo!();
//    }
//
//    fn neg(&self) -> Self;
//
//    fn neg_assign(&mut self) {
//        *self = self.neg();
//    }
//}
