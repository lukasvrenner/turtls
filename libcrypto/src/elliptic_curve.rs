mod point;
pub mod secp256r1;
pub use point::Point;

use crate::finite_field::FiniteField;

pub trait EllipticCurve: FiniteField {
    const BASE_POINT: Point<Self>;
}
