use crylib::aead::chacha::ChaCha20Poly1305;
use crylib::aead::gcm::{Aes128, AesCipher, Gcm};
use crylib::aead::{Aead, BadData, IV_SIZE, TAG_SIZE};
use crylib::hash::Sha256;

use crate::{key_schedule, CipherList};

pub(crate) struct TlsAead {
    cipher: Box<dyn Aead>,
    static_iv: [u8; IV_SIZE],
    nonce: u64,
}

impl TlsAead {
    pub(crate) fn new(secret: &[u8; Sha256::HASH_SIZE], cipher_suite: CipherList) -> Option<Self> {
        let cipher: Box<dyn Aead> = match cipher_suite.suites {
            CipherList::AES_128_GCM_SHA256 => {
                let mut key = [0; Aes128::KEY_SIZE];
                key_schedule::hkdf_expand_label(&mut key, secret, b"key", b"");
                Box::new(Gcm::<Aes128>::new(key))
            },
            CipherList::CHA_CHA_POLY1305_SHA256 => {
                let mut key = [0; ChaCha20Poly1305::KEY_SIZE];
                key_schedule::hkdf_expand_label(&mut key, secret, b"key", b"");
                Box::new(ChaCha20Poly1305::new(key))
            },
            _ => return None,
        };
        let mut static_iv = [0; IV_SIZE];
        key_schedule::hkdf_expand_label(&mut static_iv, secret, b"iv", b"");
        let nonce = 0;
        Some(Self {
            cipher,
            nonce,
            static_iv,
        })
    }
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

    pub(crate) fn encrypt_inline(
        &mut self,
        msg: &mut [u8],
        add_data: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> [u8; TAG_SIZE] {
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
