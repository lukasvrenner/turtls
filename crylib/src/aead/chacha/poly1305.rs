//! The Poly1305 authenticator.

fn clamp(r: &mut [u8; 16]) {
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[112] &= 0xfc;
}

pub fn poly1305(msg: &[u8], key: &mut [u8; 32]) -> [u8; 16] {
    let r: &mut [u8; 16] = &mut key[..16].try_into().unwrap();
    let s: &mut [u8; 16] = &mut key[16..].try_into().unwrap();
    todo!();
}
