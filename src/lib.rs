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
pub use record::Io;
use state::State;

#[repr(C)]
pub enum ShakeResult {
    Ok(Box<State>),
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
    io: Io,
) -> ShakeResult {
    todo!();
}

/// Listens for and performs a TLS handshake as the server, returning the connection state
#[no_mangle]
pub extern "C" fn shake_hands_server(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
) -> ShakeResult {
    todo!();
}
