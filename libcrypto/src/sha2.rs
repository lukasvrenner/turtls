//! The SHA2 family of hash functions.
mod hmac;
mod sha256;
mod sha512;

pub use hmac::Hmac;
pub use sha256::Sha256;
pub use sha512::Sha512;

pub trait Hasher<const H_LEN: usize> {
    fn new() -> Self;

    fn finish_with(self, msg: &[u8]) -> [u8; H_LEN];

    fn hash(msg: &[u8]) -> [u8; H_LEN];

    fn finish(self) -> [u8; H_LEN];
}

pub trait BlockHasher<const H_LEN: usize, const B_LEN: usize>: Hasher<H_LEN> {
    fn update(&mut self, block: &[u8; B_LEN]);
}

pub struct BufHasher<const H_LEN: usize, const B_LEN: usize, H>
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    hasher: H,
    buf: [u8; B_LEN],
    len: usize,
}

impl<const H_LEN: usize, const B_LEN: usize, H> BufHasher<H_LEN, B_LEN, H>
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    pub fn update_with(&mut self, msg: &[u8]) {
        let add_to_buf = core::cmp::min(B_LEN - self.len, msg.len());
        self.buf[self.len..][..add_to_buf].copy_from_slice(&msg[..add_to_buf]);

        if msg.len() < B_LEN - self.len {
            self.buf[self.len..][..msg.len()].copy_from_slice(msg);
            return;
        }

        self.buf[self.len..].copy_from_slice(&msg[..B_LEN - self.len]);
        self.hasher.update(&self.buf);

        let blocks = msg[B_LEN - self.len..].chunks_exact(B_LEN);
        let remainder = blocks.remainder();

        for block in blocks {
            self.hasher.update(block.try_into().unwrap());
        }
        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.len = remainder.len();
    }
}

impl<const H_LEN: usize, const B_LEN: usize, H> Hasher<H_LEN> for BufHasher<H_LEN, B_LEN, H>
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    fn new() -> Self {
        Self {
            hasher: H::new(),
            buf: [0; B_LEN],
            len: 0,
        }
    }

    fn finish(self) -> [u8; H_LEN] {
        self.hasher.finish_with(&self.buf[..self.len])
    }

    fn hash(msg: &[u8]) -> [u8; H_LEN] {
        <H as Hasher<H_LEN>>::hash(msg)
    }

    fn finish_with(mut self, msg: &[u8]) -> [u8; H_LEN] {
        self.update_with(msg);
        self.finish()
    }
}

impl<const H_LEN: usize, const B_LEN: usize, H> BlockHasher<H_LEN, B_LEN>
    for BufHasher<H_LEN, B_LEN, H>
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    fn update(&mut self, block: &[u8; B_LEN]) {
        self.buf[self.len..].copy_from_slice(&block[..B_LEN - self.len]);
        self.hasher.update(&self.buf);

        let remainder = &block[B_LEN - self.len..];

        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.len = remainder.len();
    }
}
