use super::sha256::Sha256;

pub fn hmac_sha256(msg: &[u8], key: &[u8]) -> [u8; Sha256::HASH_SIZE] {
    let mut ipad = [0x36; Sha256::BLOCK_SIZE];
    let mut opad = [0x5c; Sha256::BLOCK_SIZE];

    for ((ipad_byte, opad_byte), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
        *ipad_byte ^= key_byte;
        *opad_byte ^= key_byte;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update_with(&ipad);
    inner_hasher.update_with_msg(msg);
    let inner_hash = inner_hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update_with(&opad);
    hasher.update_with_msg(&inner_hash);

    hasher.finalize()
}
