use std::ffi::c_void;

use crate::{client_hello::ClientHello, record::{ContentType, Message}};

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
    pub const PREFIX_SIZE: usize = 1;
    pub fn new(shake_type: ShakeType) -> Self {

        let mut handshake = Self { msg: Message::new(ContentType::Handshake) };
        handshake[Message::PREFIIX_SIZE] = shake_type as u8;
        handshake
    }

    pub fn finish(&mut self) {
        let len_diff = &((self.len() - Message::PREFIIX_SIZE) as u32).to_be_bytes()[1..4];
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

#[repr(C)]
pub enum ShakeResult {
    Ok(*mut State),
    RngError,
}

#[no_mangle]
pub extern "C" fn shake_hands(
    // TODO: use c_size_t and c_ssize_t once stabilized
    fd: i32,
    write: extern "C" fn(i32, *const c_void, usize) -> isize,
    read: extern "C" fn(i32, *mut c_void, usize) -> isize,
) -> ShakeResult {
    let Ok(client_hello) = ClientHello::new() else {
        return ShakeResult::RngError;
    };
    write(fd, client_hello.as_ref() as *const [u8] as *const c_void, client_hello.len());

    let mut buf = [0u8; Message::MAX_SIZE];
    read(fd, &mut buf as *mut u8 as *mut c_void, buf.len());
    todo!()
}
