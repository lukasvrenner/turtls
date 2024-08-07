use crate::big_int::UBigInt;
use crate::finite_field::{FieldElement, FiniteField};

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
