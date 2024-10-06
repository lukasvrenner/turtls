//! The SHA2 family of hash functions.
mod hmac;
mod sha256;
mod sha512;

pub use hmac::hmac;
pub use sha256::Sha256;
pub use sha512::Sha512;

pub trait Hasher<const H_LEN: usize> {
    fn new() -> Self;

    fn finalize_with(self, msg: &[u8]) -> [u8; H_LEN];

    fn hash(msg: &[u8]) -> [u8; H_LEN];

    fn finalize(self) -> [u8; H_LEN];
}

pub trait BlockHasher<const H_LEN: usize, const B_LEN: usize>: Hasher<H_LEN> {
    fn update_with(&mut self, block: &[u8; B_LEN]);
}
