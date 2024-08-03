use core::marker::PhantomData;

use crate::big_int::UBigInt;
use crate::finite_field::{FiniteField, FieldElement};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Secp256r1;
impl FiniteField for Secp256r1 {
    const MODULUS: FieldElement<Self> = FieldElement(UBigInt::new([
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
    ]), PhantomData);

    const ONE: FieldElement<Self> = FieldElement(UBigInt::ONE, PhantomData);

    const ZERO: FieldElement<Self> = FieldElement(UBigInt::ZERO, PhantomData);

}
