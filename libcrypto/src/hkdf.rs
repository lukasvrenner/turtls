use crate::hash::{BlockHasher, BufHasher};
use crate::hmac::Hmac;

pub fn extract<const H_LEN: usize, const B_LEN: usize, H: BlockHasher<H_LEN, B_LEN>>(
    salt: &[u8],
    ikm: &[u8],
) -> [u8; H_LEN] {
    Hmac::<H_LEN, B_LEN, H>::auth(salt, ikm)
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
    let mut key = [0; K_LEN];

    let mut prev_mac: &[u8] = &[];
    for (i, key_chunk) in key.chunks_mut(H_LEN).enumerate() {
        let mut hmac = Hmac::<H_LEN, B_LEN, BufHasher<H_LEN, B_LEN, H>>::new(pr_key);
        hmac.update_with(prev_mac);
        hmac.update_with(info);
        let mac = hmac.finish_with(&[i as u8 + 1]);
        key_chunk.copy_from_slice(&mac[..key_chunk.len()]);
        prev_mac = key_chunk;
    }
    key
}
