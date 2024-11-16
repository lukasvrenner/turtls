use crylib::aead::{Aead, BadData, IV_SIZE, TAG_SIZE};

pub(crate) struct AeadWriter {
    cipher: Box<dyn Aead>,
    nonce: u64,
    static_iv: [u8; IV_SIZE],
}

impl AeadWriter {
    pub(crate) fn encrypt_inline(&mut self, msg: &mut [u8], add_data: &[u8]) -> [u8; TAG_SIZE] {
        let mut init_vec = self.static_iv;
        let counter = self.nonce.to_be_bytes();
        for (byte_1, byte_2) in init_vec.iter_mut().rev().zip(counter.into_iter().rev()) {
            *byte_1 ^= byte_2;
        }
        // overflow must not happen
        self.nonce = self.nonce.checked_add(1).unwrap();

        self.cipher.encrypt_inline(msg, add_data, &init_vec)
    }
}

pub(crate) struct AeadReader {
    cipher: Box<dyn Aead>,
    nonce: u64,
    static_iv: [u8; IV_SIZE],
}

impl AeadReader {
    pub(crate) fn decrypt_inline(
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
        // overflow must not happen
        self.nonce = self.nonce.checked_add(1).unwrap();

        self.cipher.decrypt_inline(msg, add_data, &init_vec, tag)
    }
}
