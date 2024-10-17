use crylib::aead;

use crate::aead::AeadWriter;
use crate::versions::LEGACY_PROTO_VERS;
use crate::State;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

    pub fn start(msg_type: ContentType) -> Self {
        let mut msg = Self {
            // TODO: consider using uninitialized memory
            buf: [0; Self::MAX_SIZE],
            len: 5,
        };
        msg[0] = msg_type as u8;
        msg[1..3].copy_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
        msg
    }

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

    pub fn extend(&mut self, amt: usize) {
        self.len += amt;
    }

    pub fn finish(&mut self) {
        let len = self.len;
        self[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    }
}

impl std::ops::Deref for Message {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len()]
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

pub struct EncryptedMessage {
    msg: Message,
    content_type: ContentType,
    padding: usize,
}

impl EncryptedMessage {
    pub fn start(content_type: ContentType, padding: usize) -> Self {
        Self {
            msg: Message::start(ContentType::ApplicationData),
            content_type,
            padding,
        }
    }

    pub fn finish(&mut self, state: &mut State) {
        let content_type = self.content_type;
        self.push(content_type as u8);

        let padding = self.padding;
        self.extend(padding + aead::TAG_SIZE);

        let (add_data, encrypted_data) = self.msg.split_at_mut(Message::PREFIIX_SIZE);
        let tag = state.aead_writer.encrypt_inline(encrypted_data, add_data);

        let tagless_len = self.len() - aead::TAG_SIZE;
        self[tagless_len..].copy_from_slice(&tag);

        self.msg.finish();
    }
}

impl std::ops::Deref for EncryptedMessage {
    type Target = Message;
    fn deref(&self) -> &Self::Target {
        &self.msg
    }
}

// TODO: should this be implemented?
impl std::ops::DerefMut for EncryptedMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.msg
    }
}
