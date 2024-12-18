use crate::big_int::UBigInt;
use crate::finite_field::{FieldElement, FiniteField};

use super::EllipticCurve;
use super::{AffinePoint, ProjectivePoint};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct Secp256r1;
// SAFETY: `Self::MODULUS` is prime.
unsafe impl FiniteField<4> for Secp256r1 {
    const MODULUS: UBigInt<4> = UBigInt([
        0xffffffffffffffff,
        0x00000000ffffffff,
        0x0000000000000000,
        0xffffffff00000001,
    ]);
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct P256Order;
// SAFETY: `Self::MODULUS` is prime.
unsafe impl FiniteField<4> for P256Order {
    const MODULUS: UBigInt<4> = UBigInt([
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
    ]);
}

impl EllipticCurve for Secp256r1 {
    const BASE_POINT: ProjectivePoint<Self> = unsafe {
        AffinePoint::new_unchecked(
            FieldElement::new_unchecked(UBigInt([
                0xf4a13945d898c296,
                0x77037d812deb33a0,
                0xf8bce6e563a440f2,
                0x6b17d1f2e12c4247,
            ])),
            FieldElement::<4, Self>::new_unchecked(UBigInt([
                0xcbb6406837bf51f5,
                0x2bce33576b315ece,
                0x8ee7eb4a7c0f9e16,
                0x4fe342e2fe1a7f9b,
            ])),
        )
        .as_projective()
    };

    const A: FieldElement<4, Self> = unsafe {
        FieldElement::new_unchecked(UBigInt([
            0xfffffffffffffffc,
            0x00000000ffffffff,
            0x0000000000000000,
            0xffffffff00000001,
        ]))
    };

    const B: FieldElement<4, Self> = unsafe {
        FieldElement::new_unchecked(UBigInt([
            0x3bce3c3e27d2604b,
            0x651d06b0cc53b0f6,
            0xb3ebbd55769886bc,
            0x5ac635d8aa3a93e7,
        ]))
    };

    type Order = P256Order;
}
