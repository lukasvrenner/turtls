use std::ffi::c_void;

use crate::record::Message;

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
    original_len: usize,
}

impl Handshake {
    fn new(msg: Message, shake_type: ShakeType) -> Self {
        let original_len = msg.len();
        let mut handshake = Self {
            msg,
            original_len,
        };
        handshake[original_len] = shake_type as u8;
        handshake
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

impl Drop for Handshake {
    fn drop(&mut self) {
        let original_len = self.original_len;
        let len_diff = &((self.len() - self.original_len) as u32).to_be_bytes()[1..4];
        self[original_len + 1..][..3].copy_from_slice(len_diff);
    }
}

#[no_mangle]
pub extern "C" fn shake_hands(
    // TODO: use c_size_t and c_ssize_t once stabilized
    fd: i32,
    write: extern "C" fn(i32, *const c_void, usize) -> isize,
    read: extern "C" fn(i32, *mut c_void, usize) -> isize,
) -> *mut State {
    let msg = todo!();;
    write(fd, msg.to_bytes() as *const u8 as *const c_void, msg.len());

    let mut buf = [0u8; Message::MAX_SIZE];
    read(fd, &mut buf as *mut u8 as *mut c_void, buf.len());
    todo!()
}
