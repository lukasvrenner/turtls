use crate::record::{ContentType, Message};

use super::State;
#[repr(u8)]
pub enum ShakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

pub struct Handshake {
    msg: Message,
}

impl Handshake {
    pub const PREFIX_SIZE: usize = 4;
    pub fn start(shake_type: ShakeType) -> Self {
        let mut handshake = Self {
            msg: Message::start(ContentType::Handshake),
        };
        handshake.push(shake_type as u8);

        // leave room for length encoding
        handshake.extend(3);
        handshake
    }

    pub fn finish(&mut self) {
        let len_diff = &((self.len() - (Message::PREFIIX_SIZE + Self::PREFIX_SIZE)) as u32).to_be_bytes()[1..4];
        self[Message::PREFIIX_SIZE + 1..][..3].copy_from_slice(len_diff);
        self.msg.finish();
    }
}

impl std::ops::Deref for Handshake {
    type Target = Message;
    fn deref(&self) -> &Message {
        &self.msg
    }
}

impl std::ops::DerefMut for Handshake {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.msg
    }
}

pub struct HandshakeRef<'a> {
    shake_type: ShakeType,
    data: &'a [u8],
}
