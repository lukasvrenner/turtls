use crate::sha2::{hmac, BlockHasher};
pub fn extract<const H_LEN: usize, const B_LEN: usize, H: BlockHasher<H_LEN, B_LEN>>(
    salt: &[u8],
    ikm: &[u8],
) -> [u8; H_LEN] {
    hmac::<H_LEN, B_LEN, H>(salt, ikm)
}

pub fn expand<
    const H_LEN: usize,
    const B_LEN: usize,
    const K_LEN: usize,
    H: BlockHasher<H_LEN, B_LEN>,
>(
    pr_key: &[u8; H_LEN],
    info: &[u8],
) -> [u8; K_LEN] {
    todo!()
}
