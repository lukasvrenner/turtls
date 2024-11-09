//! Elliptic curve cryptography.
pub mod ecdsa;
mod point;
mod secp256r1;

pub use point::affine::AffinePoint;
pub use point::projective::ProjectivePoint;
pub use secp256r1::Secp256r1;

use crate::finite_field::{FieldElement, FiniteField};

/// A trait for describining an elliptic curve over a finite field in Weierstrass form.
///
/// The curve is defined by the equation `Y^2 = X^3 + A*X + B`.
// TODO: make this generic over any size N once const generic operators are stabilized.
pub trait EllipticCurve: FiniteField<4> {
    /// The generator point used for elliptic-curve cryptography.
    const BASE_POINT: ProjectivePoint<Self>;

    /// The linear-term coefficient of the curve.
    const A: FieldElement<4, Self>;

    /// The constant-term coefficient of the curve.
    const B: FieldElement<4, Self>;

    type Order: FiniteField<4>;
}
