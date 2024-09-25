//! Elliptic curve cryptography.
pub mod ecdsa;
mod point;
mod secp256r1;

use crate::big_int::UBigInt;
pub use point::affine::AffinePoint;
pub use point::projective::ProjectivePoint;
pub use secp256r1::Secp256r1;

use crate::finite_field::{FieldElement, FiniteField};

/// A trait for describining an elliptic curve over a finite field in Weierstrass form.
///
/// The curve is defined by the equation `Y^2 = X^3 + A*X + B`.
pub trait EllipticCurve: FiniteField {
    /// The generator point used for elliptic-curve cryptography.
    const BASE_POINT: AffinePoint<Self>;

    /// The linear-term coefficient of the curve.
    const A: FieldElement<Self>;

    /// The constant-term coefficient of the curve.
    const B: FieldElement<Self>;

    const ORDER: UBigInt<4>;
}
