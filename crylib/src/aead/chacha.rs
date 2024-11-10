//! The ChaCha20 stream cipher, Poly1305 authenticator, and ChaCha20-Poly1305 AEAD.
//!
//! Note: Poly1305 and ChaCha20-Poly1305 are incomplete.

use poly1305::{poly1305_key_gen, Poly1305};

use super::{Aead, BadData, IV_SIZE, TAG_SIZE};
pub mod chacha20;
pub mod poly1305;

pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl Aead for ChaCha20Poly1305 {
    fn encrypt_inline(
        &self,
        msg: &mut [u8],
        add_data: &[u8],
        init_vector: &[u8; super::IV_SIZE],
    ) -> [u8; super::TAG_SIZE] {
        chacha20::encrypt_inline(msg, &self.key, init_vector, 1);
        poly_auth(&self.key, init_vector, add_data, msg)
    }

    fn decrypt_inline(
        &self,
        msg: &mut [u8],
        add_data: &[u8],
        init_vector: &[u8; super::IV_SIZE],
        tag: &[u8; super::TAG_SIZE],
    ) -> Result<(), super::BadData> {
        let gen_tag = poly_auth(&self.key, init_vector, add_data, msg);
        if tag != &gen_tag {
            return Err(BadData);
        }
        chacha20::encrypt_inline(msg, &self.key, init_vector, 1);
        Ok(())
    }
}

fn poly_auth(key: &[u8; 32], iv: &[u8; IV_SIZE], add_data: &[u8], cipher_text: &[u8]) -> [u8; TAG_SIZE] {
        let one_time_key = poly1305_key_gen(key, iv);

        let mut poly = Poly1305::new(&one_time_key);

        poly.update_with(add_data);
        poly.update_with(cipher_text);

        let mut lens = [0; 16];
        lens[..size_of::<u64>()].copy_from_slice(&(add_data.len() as u64).to_be_bytes());
        lens[size_of::<u64>()..].copy_from_slice(&(cipher_text.len() as u64).to_be_bytes());

        poly.update(&lens);
        poly.finish()
}
