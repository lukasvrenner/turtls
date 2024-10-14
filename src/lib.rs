//! This crate has the long-term goal of
//!becoming a fully compliant TLS 1.3 library, with C bindings.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]

mod aead;
mod alert;
mod cipher_suites;
mod client_hello;
mod extensions;
mod handshake;
mod key_schedule;
mod record;
mod server_hello;
mod versions;

use aead::{AeadReader, AeadWriter};
pub use handshake::shake_hands;
use record::ContentType;
use versions::LEGACY_PROTO_VERS;

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,
}

struct Message {
    contents: [u8; Self::MAX_SIZE],
}

impl Message {
    pub const MAX_SIZE: usize = 0x4006;

    pub fn data_len(&self) -> u16 {
        u16::from_be_bytes(self[3..5].try_into().unwrap())
    }

    pub fn len(&self) -> usize {
        self.data_len() as usize + 5
    }

    fn increment_len(&mut self) {
        let new_len = (self.data_len() + 1).to_be_bytes();
        self[3..5].copy_from_slice(&new_len);
    }

    fn extend_len(&mut self, amount: u16) {
        let new_len = (self.data_len() + amount).to_be_bytes();
        self[3..5].copy_from_slice(&new_len);
    }

    pub fn push(&mut self, val: u8) {
        let len = self.data_len() as usize;
        self[len] = val;
        self.increment_len();
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let len = self.data_len() as usize;
        self[len..][..slice.len()].copy_from_slice(slice);
        self.extend_len(slice.len() as u16);
    }

    pub fn new(msg_type: ContentType) -> Self {
        let mut msg = Self {contents: [0; Self::MAX_SIZE] };
        msg[1..3].copy_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
        msg.reset(msg_type);
        msg
    }

    pub fn reset(&mut self, msg_type: ContentType) {
        self[0] = msg_type as u8;
        self[3] = 0;
        self[4] = 0;
    }

    pub fn as_bytes(&self) -> &[u8; Self::MAX_SIZE] {
        self
    }
}

impl std::ops::Deref for Message {
    type Target = [u8; Self::MAX_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

// TODO: should this be implemented?
impl std::ops::DerefMut for Message {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.contents
    }
}

impl std::borrow::Borrow<[u8]> for Message {
    fn borrow(&self) -> &[u8] {
        &self.contents
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.contents
    }
}
