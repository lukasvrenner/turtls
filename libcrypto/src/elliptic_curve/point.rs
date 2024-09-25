pub mod affine;
pub mod projective;

pub use affine::AffinePoint;
pub use projective::ProjectivePoint;
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
