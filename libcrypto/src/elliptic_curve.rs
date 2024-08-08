//! Elliptic curve cryptography.
mod ecdsa;
mod point;
mod secp256r1;
pub use point::Point;
pub use secp256r1::Secp256r1;

use crate::finite_field::{FieldElement, FiniteField};

/// A trait for describining an elliptic curve over a finite field.
pub trait EllipticCurve: FiniteField {
    const BASE_POINT: Point<Self>;

    const A: FieldElement<Self>;

    const B: FieldElement<Self>;
}
