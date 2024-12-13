use crylib::aead::chacha::ChaCha20Poly1305;
use crylib::aead::gcm::{Aes128, AesCipher, Gcm};
use crylib::aead::{Aead, BadData, IV_SIZE, TAG_SIZE};
use crylib::hash::{Hasher, Sha256};
use crylib::hkdf;

use crate::cipher_suites::TurtlsCipherList;
use crate::key_schedule;
use crate::state::GlobalState;

enum ManyAead {
    Aes128Gcm {
        writer: Gcm<Aes128>,
        reader: Gcm<Aes128>,
    },
    ChaChaPoly {
        writer: ChaCha20Poly1305,
        reader: ChaCha20Poly1305,
    },
}

impl ManyAead {
    fn encrypt_inline(
        &mut self,
        msg: &mut [u8],
        add_data: &[u8],
        iv: &[u8; IV_SIZE],
    ) -> [u8; TAG_SIZE] {
        match self {
            Self::Aes128Gcm { writer, .. } => writer.encrypt_inline(msg, add_data, iv),
            Self::ChaChaPoly { writer, .. } => writer.encrypt_inline(msg, add_data, iv),
        }
    }

    fn decrypt_inline(
        &mut self,
        msg: &mut [u8],
        add_data: &[u8],
        iv: &[u8; IV_SIZE],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BadData> {
        match self {
            Self::Aes128Gcm { reader, .. } => reader.decrypt_inline(msg, add_data, iv, tag),
            Self::ChaChaPoly { reader, .. } => reader.decrypt_inline(msg, add_data, iv, tag),
        }
    }
}

pub(crate) struct TlsAead {
    aead: ManyAead,
    write_iv: [u8; IV_SIZE],
    write_nonce: u64,
    read_iv: [u8; IV_SIZE],
    read_nonce: u64,
}

impl TlsAead {
    const NONCE_INIT: u64 = 0;

    pub(crate) fn new(
        write_secret: &[u8; Sha256::HASH_SIZE],
        read_secret: &[u8; Sha256::HASH_SIZE],
        cipher: TurtlsCipherList,
    ) -> Option<Self> {
        let mut write_iv = [0; IV_SIZE];
        key_schedule::hkdf_expand_label(&mut write_iv, write_secret, b"iv", b"");

        let mut read_iv = [0; IV_SIZE];
        key_schedule::hkdf_expand_label(&mut read_iv, read_secret, b"iv", b"");

        match cipher.suites {
            TurtlsCipherList::TURTLS_AES_128_GCM_SHA256 => {
                let mut write_key = [0; Aes128::KEY_SIZE];
                key_schedule::hkdf_expand_label(&mut write_key, write_secret, b"key", b"");

                let mut read_key = [0; Aes128::KEY_SIZE];
                key_schedule::hkdf_expand_label(&mut read_key, read_secret, b"key", b"");

                Some(Self {
                    aead: ManyAead::Aes128Gcm {
                        writer: Gcm::<Aes128>::new(write_key),
                        reader: Gcm::<Aes128>::new(read_key),
                    },
                    write_iv,
                    write_nonce: Self::NONCE_INIT,
                    read_iv,
                    read_nonce: Self::NONCE_INIT,
                })
            },
            TurtlsCipherList::TURTLS_CHA_CHA_POLY1305_SHA256 => {
                let mut write_key = [0; ChaCha20Poly1305::KEY_SIZE];
                key_schedule::hkdf_expand_label(&mut write_key, write_secret, b"key", b"");

                let mut read_key = [0; ChaCha20Poly1305::KEY_SIZE];
                key_schedule::hkdf_expand_label(&mut read_key, read_secret, b"key", b"");

                Some(Self {
                    aead: ManyAead::ChaChaPoly {
                        writer: ChaCha20Poly1305::new(write_key),
                        reader: ChaCha20Poly1305::new(read_key),
                    },
                    write_iv,
                    write_nonce: Self::NONCE_INIT,
                    read_iv,
                    read_nonce: Self::NONCE_INIT,
                })
            },
            _ => None,
        }
    }

    pub(crate) fn decrypt_inline(
        &mut self,
        msg: &mut [u8],
        add_data: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), BadData> {
        let mut init_vec = self.read_iv;
        let counter = self.read_nonce.to_be_bytes();
        for (byte_1, byte_2) in init_vec.iter_mut().rev().zip(counter.into_iter().rev()) {
            *byte_1 ^= byte_2;
        }
        // overflow must not happen
        self.read_nonce = self.read_nonce.checked_add(1).unwrap();

        self.aead.decrypt_inline(msg, add_data, &init_vec, tag)
    }

    pub(crate) fn encrypt_inline(&mut self, msg: &mut [u8], add_data: &[u8]) -> [u8; TAG_SIZE] {
        let mut init_vec = self.write_iv;
        let counter = self.write_nonce.to_be_bytes();
        for (byte_1, byte_2) in init_vec.iter_mut().rev().zip(counter.into_iter().rev()) {
            *byte_1 ^= byte_2;
        }
        // overflow must not happen
        self.write_nonce = self.write_nonce.checked_add(1).unwrap();

        self.aead.encrypt_inline(msg, add_data, &init_vec)
    }

    pub(crate) fn shake_aead(
        global_state: &mut GlobalState,
        dh_secret: &[u8],
        cipher: TurtlsCipherList,
    ) -> Option<Self> {
        let salt =
            key_schedule::derive_secret(&global_state.secret, b"derived", &Sha256::hash(b""));

        global_state.secret = hkdf::extract::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
            &dh_secret, &salt,
        );

        let transcript = global_state.transcript.get();

        let cli_shake_traf_secret =
            key_schedule::derive_secret(&global_state.secret, b"c hs traffic", &transcript);
        let ser_shake_traf_secret =
            key_schedule::derive_secret(&global_state.secret, b"s hs traffic", &transcript);

        Self::new(&cli_shake_traf_secret, &ser_shake_traf_secret, cipher)
    }
}
