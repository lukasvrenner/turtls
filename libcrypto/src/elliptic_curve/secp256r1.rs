use crate::big_int::UBigInt;
use crate::finite_field::{FieldElement, FiniteField};

use super::EllipticCurve;
use super::Point;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct Secp256r1;
impl FiniteField for Secp256r1 {
    const MODULUS: UBigInt<4> = UBigInt::new([
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
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
}
