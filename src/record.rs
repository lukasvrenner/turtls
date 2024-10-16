use crate::aead::AeadWriter;
use crate::versions::LEGACY_PROTO_VERS;

#[repr(u8)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

pub struct Message {
    buf: [u8; Message::MAX_SIZE],
    len: usize,
}

impl Message {
    pub const MAX_SIZE: usize = 0x4006;
    pub const PREFIIX_SIZE: usize = 5;

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, val: u8) {
        let len = self.len();
        self[len] = val;
        self.len += 1;
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let len = self.len;
        self[len..][..slice.len()].copy_from_slice(slice);
        self.len += slice.len();
    }

    pub fn new(msg_type: ContentType) -> Self {
        let mut msg = Self {
            buf: [0; Self::MAX_SIZE],
            len: 5,
        };
        msg[0] = msg_type as u8;
        msg[1..3].copy_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
        msg
    }

    pub fn reset(&mut self, msg_type: ContentType) {
        self[0] = msg_type as u8;
        self[3] = 0;
        self[4] = 0;
    }

    pub fn finish(&mut self) {
        let len = self.len;
        self[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    }
}

impl std::ops::Deref for Message {
    type Target = [u8; Message::MAX_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

// TODO: should this be implemented?
impl std::ops::DerefMut for Message {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl std::borrow::Borrow<[u8]> for Message {
    fn borrow(&self) -> &[u8] {
        &self.buf
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl AsMut<[u8]> for Message {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}
