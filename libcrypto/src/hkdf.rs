use crate::sha2::{hmac, BlockHasher};
pub fn extract<
    const K_LEN: usize,
    const H_LEN: usize,
    const B_LEN: usize,
    H: BlockHasher<H_LEN, B_LEN>,
>(
    salt: &[u8],
    ikm: &[u8],
) -> [u8; H_LEN] {
    hmac::<H_LEN, B_LEN, H>(salt, ikm)
}

pub fn expand<const H_SIZE: usize, const B_SIZE: usize, H: BlockHasher<H_SIZE, B_SIZE>>(
    pr_key: &[u8; H_SIZE],
    info: &[u8],
    key_buf: &mut [u8],
) {
    //key_buf[0] = hmac(pr_key, )
    todo!()
}
