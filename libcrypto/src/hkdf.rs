use crate::sha2::{BlockHasher, BufHasher, Hmac};
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
    let div = K_LEN / H_LEN;
    let mut prev_mac: &[u8] = &[];
    for i in 0..div {
        let mut hmac = Hmac::<H_LEN, B_LEN, BufHasher<H_LEN, B_LEN, H>>::new(pr_key);
        hmac.update_with(prev_mac);
        hmac.update_with(info);
        let mac = hmac.finish_with(&[i as u8 + 1]);
        key[i * H_LEN..][..H_LEN].copy_from_slice(&mac);
        prev_mac = &key[i * H_LEN..][..H_LEN];
    }
    let mut hmac = Hmac::<H_LEN, B_LEN, BufHasher<H_LEN, B_LEN, H>>::new(pr_key);
    hmac.update_with(info);
    let mac = hmac.finish_with(&[div as u8]);
    key[div..].copy_from_slice(&mac[..H_LEN - div]);
    key
}
