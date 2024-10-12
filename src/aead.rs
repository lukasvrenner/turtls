use crylib::aead::{Aead, BadData, IV_SIZE, TAG_SIZE};

pub struct AeadWriter {
    cipher: Box<dyn Aead>,
    nonce: u64,
    static_iv: [u8; IV_SIZE],
}

impl AeadWriter {
    pub fn encrypt_inline(&mut self, msg: &mut [u8], add_data: &[u8]) -> [u8; TAG_SIZE] {
        let mut init_vec = self.static_iv;
        let counter = self.nonce.to_be_bytes();
        for (byte_1, byte_2) in init_vec.iter_mut().rev().zip(counter.into_iter().rev()) {
            *byte_1 ^= byte_2;
        }
        // TODO: add an overflow check?
        self.nonce += 1;

        self.cipher.encrypt_inline(msg, add_data, &init_vec)
    }
}

pub struct AeadReader {
    cipher: Box<dyn Aead>,
    nonce: u64,
    static_iv: [u8; IV_SIZE],
}

impl AeadReader {
    pub fn decrypt_inline(
        &mut self,
        msg: &mut [u8],
        add_data: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BadData> {
        let mut init_vec = self.static_iv;
        let counter = self.nonce.to_be_bytes();
        for (byte_1, byte_2) in init_vec.iter_mut().rev().zip(counter.into_iter().rev()) {
            *byte_1 ^= byte_2;
        }
        // TODO: add an overflow check?
        self.nonce += 1;

        self.cipher.decrypt_inline(msg, add_data, &init_vec, tag)
    }
}
