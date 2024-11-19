pub mod chacha;
pub mod gcm;

pub const IV_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// An error that is returned when an encrypted message's tag
/// does not match its generated tag
///
/// If this error is found, the message cannot be considered safe
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BadData;

impl core::fmt::Display for BadData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "tag did not match data")
    }
}

impl core::error::Error for BadData {}

pub trait Aead {
    fn encrypt_inline(&self, msg: &mut [u8], add_data: &[u8], iv: &[u8; IV_SIZE])
        -> [u8; TAG_SIZE];

    fn encrypt(
        &self,
        buf: &mut [u8],
        plain_text: &[u8],
        add_data: &[u8],
        iv: &[u8; IV_SIZE],
    ) -> [u8; TAG_SIZE] {
        buf[..plain_text.len()].copy_from_slice(&plain_text);
        self.encrypt_inline(&mut buf[..plain_text.len()], add_data, iv)
    }

    fn decrypt_inline(
        &self,
        msg: &mut [u8],
        add_data: &[u8],
        iv: &[u8; IV_SIZE],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BadData>;

    fn decrypt(
        &self,
        buf: &mut [u8],
        cipher_text: &[u8],
        add_data: &[u8],
        iv: &[u8; IV_SIZE],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BadData> {
        buf[..cipher_text.len()].copy_from_slice(&cipher_text);
        self.decrypt_inline(&mut buf[..cipher_text.len()], add_data, iv, tag)
    }
}
