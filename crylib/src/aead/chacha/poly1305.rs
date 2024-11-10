//! The Poly1305 authenticator.

use crate::{
    aead::IV_SIZE,
    big_int::UBigInt,
    finite_field::{FieldElement, FiniteField},
};

fn clamp(r: &mut [u8; 16]) {
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[112] &= 0xfc;
}

pub struct Poly1305 {
    r: FieldElement<3, PolyField>,
    s: FieldElement<3, PolyField>,
    accum: FieldElement<3, PolyField>,
}

impl Poly1305 {
    pub fn auth(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
        let mut poly = Self::new(key);
        poly.update_with(msg);
        poly.finish()
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = key[..16].try_into().unwrap();
        clamp(&mut r);

        let r: UBigInt<3> = UBigInt::<2>::from_le_bytes(r).resize();
        let r: FieldElement<3, PolyField> = unsafe { FieldElement::new_unchecked(r) };

        let s: UBigInt<3> = UBigInt::<2>::from_le_bytes(key[16..].try_into().unwrap()).resize();
        let s: FieldElement<3, PolyField> = unsafe { FieldElement::new_unchecked(s) };

        let accum: FieldElement<3, PolyField> = FieldElement::ZERO;

        Self { r, s, accum }
    }

    pub fn update(&mut self, msg: &[u8; 16]) {
        let mut as_int: UBigInt<3> =
            UBigInt::<2>::from_le_bytes(*msg).resize();
        as_int.add_bit();
        // SAFETY: as_int is guaranteed to be less than `PolyField::MODULUS`.
        let as_fe: FieldElement<3, PolyField> = unsafe { FieldElement::new_unchecked(as_int) };
        self.accum.add_assign(&as_fe);
        self.accum.mul_assign(&self.r);
    }

    /// Updates `self` with `msg`, padding with zeros if necessary.
    pub fn update_with(&mut self, msg: &[u8]) {
        let blocks = msg.chunks_exact(16);
        let remainder = blocks.remainder();
        for block in blocks {
            self.update(block.try_into().unwrap());
        }
        let mut last_block = [0; 16];
        last_block[..remainder.len()].copy_from_slice(remainder);
        self.update(&last_block);
    }

    pub fn finish(&mut self) -> [u8; 16] {
        self.accum.add_assign(&self.s);
        self.accum.inner().resize::<2>().to_le_bytes()
    }
}

pub fn poly1305_key_gen(key: &[u8; 32], iv: &[u8; IV_SIZE]) -> [u8; 32] {
    let block = super::chacha20::block(key, iv, 0);
    block[..32].try_into().unwrap()
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
struct PolyField;

// SAFETY: MODULUS is prime.
unsafe impl FiniteField<3> for PolyField {
    const MODULUS: UBigInt<3> = UBigInt([0xfffffffffffffffb, 0xffffffffffffffff, 0x30]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_gen() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let output = [
            0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2,
            0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2,
            0xfd, 0xd1, 0xa6, 0x46,
        ];
        assert_eq!(poly1305_key_gen(&key, &nonce), output);
    }
}
