//! The SHA2 family of hash functions.
mod hmac;
mod sha256;
mod sha512;

pub use hmac::hmac;
pub use sha256::Sha256;
pub use sha512::Sha512;

pub trait Hasher<const HASH_SIZE: usize> {
    fn new() -> Self;

    fn update_with_msg(&mut self, msg: &[u8]);

    fn finalize(self) -> [u8; HASH_SIZE];

    fn hash() -> [u8; HASH_SIZE];
}

pub trait BlockHasher<const H_SIZE: usize, const B_SIZE: usize>: Hasher<H_SIZE> {
    fn update_with(&mut self, block: &[u8; B_SIZE]);
}
