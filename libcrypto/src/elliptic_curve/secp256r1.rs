use crate::big_int::UBigInt;
use crate::finite_field::{FieldElement, FiniteField};

use super::EllipticCurve;
use super::Point;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct Secp256r1;
// SAFETY: `Self::MODULUS` is prime.
unsafe impl FiniteField for Secp256r1 {
    const MODULUS: UBigInt<4> = UBigInt::new([
        0xffffffffffffffff,
        0x00000000ffffffff,
        0x0000000000000000,
        0xffffffff00000001,
    ]);

    // SAFETY: `UBigInt::ONE` is less than `Self::MODULUS`
    const ONE: FieldElement<Self> = unsafe { FieldElement::new_unchecked(UBigInt::ONE) };

    // SAFETY: `UBigInt::ZERO` is less than `Self::MODULUS`
    const ZERO: FieldElement<Self> = unsafe { FieldElement::new_unchecked(UBigInt::ZERO) };
}

impl EllipticCurve for Secp256r1 {
    const BASE_POINT: Point<Self> = unsafe {
        Point {
            x: FieldElement::new_unchecked(UBigInt::new([
                0xf4a13945d898c296,
                0x77037d812deb33a0,
                0xf8bce6e563a440f2,
                0x6b17d1f2e12c4247,
            ])),
            y: FieldElement::new_unchecked(UBigInt::new([
                0xcbb6406837bf51f5,
                0x2bce33576b315ece,
                0x8ee7eb4a7c0f9e16,
                0x4fe342e2fe1a7f9b,
            ])),
        }
    };

    const A: FieldElement<Self> = unsafe {
        FieldElement::new_unchecked(UBigInt([
            0xfffffffffffffffc,
            0x00000000ffffffff,
            0x0000000000000000,
            0xffffffff00000001,
        ]))
    };

    const B: FieldElement<Self> = unsafe {
        FieldElement::new_unchecked(UBigInt([
            0x3bce3c3e27d2604b,
            0x651d06b0cc53b0f6,
            0xb3ebbd55769886bc,
            0x5ac635d8aa3a93e7,
        ]))
    };
}
