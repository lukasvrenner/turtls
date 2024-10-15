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

pub fn plaintext_record(msg_type: ContentType, msg_data: impl FnOnce(&mut Message)) -> Message {
    let mut msg = Message::new(msg_type);
    msg_data(&mut msg);
    msg
}

pub fn encrypted_record(
    msg_type: ContentType,
    msg_data: impl FnOnce(&mut Message),
    aead_state: &mut AeadWriter,
) -> Message {
    let mut msg = Message::new(ContentType::ApplicationData);
    msg_data(&mut msg);
    msg.push(msg_type as u8);

    let split_msg = msg.split_at_mut(5);
    let tag = aead_state.encrypt_inline(split_msg.1, split_msg.0);
    msg.extend_from_slice(&tag);
    msg
}

pub struct Message {
    contents: [u8; Self::MAX_SIZE],
    len: usize,
}

impl Message {
    pub const MAX_SIZE: usize = 0x4006;

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
        let mut msg = Self {contents: [0; Self::MAX_SIZE], len: 5, };
        msg[1..3].copy_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
        msg.reset(msg_type);
        msg
    }

    pub fn reset(&mut self, msg_type: ContentType) {
        self[0] = msg_type as u8;
        self[3] = 0;
        self[4] = 0;
    }

    pub fn to_bytes(&mut self) -> &mut [u8; Self::MAX_SIZE] {
        let len = self.len;
        self[3..5].copy_from_slice(&(len as u16).to_be_bytes());
        &mut self.contents
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
