//! The Poly1305 authenticator.

use crate::{big_int::UBigInt, finite_field::{FieldElement, FiniteField}};

fn clamp(r: &mut [u8; 16]) {
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[112] &= 0xfc;
}

pub fn poly1305(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let r: UBigInt<3> = UBigInt::<2>::from_le_bytes(key[..16].try_into().unwrap()).resize();
    let r: FieldElement<3, PolyField> = unsafe {
        FieldElement::new_unchecked(r)
    };
    let s: UBigInt<3> = UBigInt::<2>::from_le_bytes(key[16..].try_into().unwrap()).resize();
    let s: FieldElement<3, PolyField> = unsafe {
        FieldElement::new_unchecked(s)
    };
    let mut accum: FieldElement<3, PolyField> = FieldElement::ZERO;
    for block in msg.chunks(16) {
        let mut as_int: UBigInt<3> = UBigInt::<2>::from_le_bytes(block.try_into().unwrap()).resize();
        as_int.add_bit();
        // SAFETY: as_int is guaranteed to be less than `PolyField::MODULUS`.
        let as_fe: FieldElement<3, PolyField> = unsafe {
            FieldElement::new_unchecked(as_int)
        };
        accum.add_assign(&as_fe);
        accum.mul_assign(&r);
    }
    accum.add_assign(&s);
    accum.inner().resize::<2>().to_le_bytes()
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
struct PolyField;

// SAFETY: MODULUS is prime.
unsafe impl FiniteField<3> for PolyField {
    const MODULUS: UBigInt<3> = UBigInt([0xfffffffffffffffb, 0xffffffffffffffff, 0x30,]);
}
