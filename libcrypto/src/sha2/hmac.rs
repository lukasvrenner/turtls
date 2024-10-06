use super::BlockHasher;

pub fn hmac<const H_LEN: usize, const B_LEN: usize, H: BlockHasher<H_LEN, B_LEN>>(
    msg: &[u8],
    key: &[u8],
) -> [u8; H_LEN] {
    let mut ipad = [0x36; B_LEN];
    let mut opad = [0x5c; B_LEN];

    for ((ipad_byte, opad_byte), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
        *ipad_byte ^= key_byte;
        *opad_byte ^= key_byte;
    }

    let mut inner_hasher = H::new();
    inner_hasher.update_with(&ipad);
    let inner_hash = inner_hasher.finalize_with(msg);

    let mut hasher = H::new();
    hasher.update_with(&opad);

    hasher.finalize_with(&inner_hash)
}
