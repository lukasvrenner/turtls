use std::ffi::c_void;

use crate::client_hello::client_hello;

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
    write: extern "C" fn(*const c_void, usize),
    read: extern "C" fn(*mut c_void, usize) -> usize,
) -> *mut State {
    let mut msg = Vec::new();
    client_hello(&mut msg);
    write(&msg as &[u8] as *const [u8] as *const c_void, msg.len());
    let mut buf: [u8; 1024] = [0; 1024];
    read(&mut buf as *mut [u8; 1024] as *mut c_void, buf.len());
    todo!()
}
