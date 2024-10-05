use super::sha256::{be_bytes_to_u32_array, Sha256, to_be_bytes_from_hash, BLOCK_SIZE, HASH_SIZE};

pub fn hmac_sha256(msg: &[u8], key: &[u8]) {
    let mut ipad = [0x36; BLOCK_SIZE];
    let mut opad = [0x5c; BLOCK_SIZE];

    for ((ipad_byte, opad_byte), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
        *ipad_byte ^= key_byte;
        *opad_byte ^= key_byte;
    }

    let mut inner_hash = Sha256::new();
    todo!()
}
