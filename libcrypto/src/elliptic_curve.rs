//! Elliptic curve cryptography.
mod point;
mod secp256r1;
mod ecdsa;
pub use secp256r1::Secp256r1;
pub use point::Point;

use crate::finite_field::FiniteField;

pub trait EllipticCurve: FiniteField {
    const BASE_POINT: Point<Self>;
}
