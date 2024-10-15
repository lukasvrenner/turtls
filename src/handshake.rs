use std::ffi::c_void;

use crate::{client_hello::client_hello, record::{plaintext_record, ContentType}, Message};

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

#[no_mangle]
pub extern "C" fn shake_hands(
    // TODO: use c_size_t and c_ssize_t once stabilized
    fd: i32,
    write: extern "C" fn(i32, *const c_void, usize) -> isize,
    read: extern "C" fn(i32, *mut c_void, usize) -> isize,
) -> *mut State {
    let msg = plaintext_record(ContentType::Handshake, client_hello);
    write(fd, msg.as_bytes() as *const u8 as *const c_void, msg.len());

    let mut buf = [0u8; Message::MAX_SIZE];
    read(fd, &mut buf as *mut u8 as *mut c_void, buf.len());
    todo!()
}
