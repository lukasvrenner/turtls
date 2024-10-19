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
use cipher_suites::{CipherSuite, GroupKeys};
use client_hello::ClientHello;
use record::Message;
use std::ffi::c_void;

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,

    group_keys: GroupKeys,
}

#[repr(C)]
pub enum ShakeResult {
    Ok(*mut State),
    RngError,
}

#[no_mangle]
pub extern "C" fn client_shake_hands(
    // TODO: use c_size_t and c_ssize_t once stabilized
    fd: i32,
    write: extern "C" fn(i32, *const c_void, usize) -> isize,
    read: extern "C" fn(i32, *mut c_void, usize) -> isize,
) -> ShakeResult {
    let sup_suites = [CipherSuite::Aes128CcmSha256];
    let Ok(client_hello) = ClientHello::new(&sup_suites) else {
        return ShakeResult::RngError;
    };
    write(
        fd,
        client_hello.as_ref() as *const [u8] as *const c_void,
        client_hello.len(),
    );

    let mut buf = [0u8; Message::MAX_SIZE];
    read(fd, &mut buf as *mut u8 as *mut c_void, buf.len());
    todo!()
}
