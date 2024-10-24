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
mod state;
mod versions;

use aead::{AeadReader, AeadWriter};
use cipher_suites::{CipherSuite, GroupKeys};
use client_hello::ClientHello;
use crylib::big_int::UBigInt;
use crylib::ec::Secp256r1;
use crylib::finite_field::FieldElement;
use getrandom::{getrandom, Error};
use state::State;
use std::ffi::c_void;

#[repr(C)]
pub enum ShakeResult {
    Ok(*mut State),
    RngError,
}

impl From<Error> for ShakeResult {
    fn from(_: Error) -> Self {
        ShakeResult::RngError
    }
}

/// Performs a TLS handshake as the client, returning the connection state
#[no_mangle]
pub extern "C" fn shake_hands_client(
    // TODO: use c_size_t and c_ssize_t once stabilized
    write: extern "C" fn(*const c_void, usize, *const c_void) -> isize,
    read: extern "C" fn(*mut c_void, usize, *const c_void) -> isize,
    ctx: *const c_void,
) -> ShakeResult {
    let mut state = State::new_uninit();
    let mut buf = [0; FieldElement::<Secp256r1>::LEN * size_of::<u64>()];
    if getrandom(&mut buf).is_err() {
        return ShakeResult::RngError;
    }
    let priv_key = FieldElement::new(UBigInt::<4>::from_be_bytes(buf));
    let sup_suites = [CipherSuite::Aes128GcmSha256];
    let group_keys = GroupKeys {
        secp256r1: priv_key,
    };
    // TODO: use ? once Try trait is stabilized
    let Ok(client_hello) = ClientHello::new(&sup_suites, &group_keys) else {
        return ShakeResult::RngError;
    };
    write(
        client_hello.as_ref() as *const [u8] as *const c_void,
        client_hello.len(),
        ctx,
    );

    let mut buf = [0u8; Record::MAX_SIZE];
    let len = read(&mut buf as *mut u8 as *mut c_void, buf.len(), ctx);
    println!("{len}");
    todo!()
}

/// Listens for and performs a TLS handshake as the server, returning the connection state
#[no_mangle]
pub extern "C" fn shake_hands_server(
    // TODO: use c_size_t and c_ssize_t once stabilized
    write: extern "C" fn(*const c_void, usize, *const c_void) -> isize,
    read: extern "C" fn(*mut c_void, usize, *const c_void) -> isize,
    ctx: *const c_void,
) -> ShakeResult {
    let mut buf = [0u8; Record::MAX_SIZE];
    read(&mut buf as *mut [u8] as *mut c_void, buf.len(), ctx);
    todo!()
}
