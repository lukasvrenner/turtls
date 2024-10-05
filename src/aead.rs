use libcrypto::aead::{Aead, IV_SIZE};

pub struct AeadState {
    cipher: Box<dyn Aead>,
    nonce: u64,
    static_iv: [u8; IV_SIZE],
}

impl AeadState {
    pub fn encrypt_inline(&mut self, msg: &mut[u8], add_data: &[u8]) {
        let mut init_vec = self.static_iv;
        let counter = self.nonce.to_be_bytes();
        for (byte_1, byte_2) in init_vec.iter_mut().rev().zip(counter.into_iter().rev()) {
            *byte_1 ^= byte_2;
        }
        self.cipher.encrypt_inline(msg, add_data, &init_vec);
        // TODO: add an overflow check?
        self.nonce += 1;
    }
}
