pub mod chacha;
pub mod gcm;

pub const IV_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub trait Aead {
    fn encrypt_inline(
        &self,
        plain_text: &mut [u8],
        add_data: &[u8],
        init_vector: &[u8; IV_SIZE],
    ) -> [u8; 16];
}
