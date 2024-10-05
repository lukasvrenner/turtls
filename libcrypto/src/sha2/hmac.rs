use super::BlockHasher;

pub fn hmac<const B_SIZE: usize, const H_SIZE: usize, H: BlockHasher<H_SIZE, B_SIZE>>(
    msg: &[u8],
    key: &[u8],
) -> [u8; H_SIZE] {
    let mut ipad = [0x36; B_SIZE];
    let mut opad = [0x5c; B_SIZE];

    for ((ipad_byte, opad_byte), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
        *ipad_byte ^= key_byte;
        *opad_byte ^= key_byte;
    }

    let mut inner_hasher = H::new();
    inner_hasher.update_with(&ipad);
    inner_hasher.update_with_msg(msg);
    let inner_hash = inner_hasher.finalize();

    let mut hasher = H::new();
    hasher.update_with(&opad);
    hasher.update_with_msg(&inner_hash);

    hasher.finalize()
}
