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

use std::time::Duration;

use aead::{AeadReader, AeadWriter};
pub use alert::AlertDescription;
use cipher_suites::{CipherSuite, CipherSuites, GroupKeys};
use client_hello::{CliHelError, ClientHello};
use crylib::big_int::UBigInt;
use crylib::ec::Secp256r1;
use crylib::finite_field::FieldElement;
use extensions::Extensions;
use getrandom::{getrandom, Error};
use record::ContentType;
pub use record::Io;
use state::State;

#[must_use]
#[repr(C)]
pub enum ShakeResult {
    Ok(Box<State>),
    RngError,
    IoError,
    RecievedAlert(AlertDescription),
}

impl From<CliHelError> for ShakeResult {
    fn from(value: CliHelError) -> Self {
        match value {
            CliHelError::IoError => Self::IoError,
            CliHelError::RngError => Self::RngError,
        }
    }
}

/// Performs a TLS handshake as the client, returning the connection state
#[no_mangle]
pub extern "C" fn shake_hands_client(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
) -> ShakeResult {
    let cipher_suites = CipherSuites::default();
    let extensions = Extensions::default();
    let mut state = State::new_uninit();
    let record_layer = State::init_buf_with(&mut state, ContentType::Handshake, io);
    let client_hello = ClientHello {
        cipher_suites: &cipher_suites,
        extensions: &extensions,
    };

    let keys = GroupKeys::generate(extensions.supported_groups);
    if let Err(err) = client_hello.write_to(record_layer, &keys) {
        return err.into();
    }

    let timeout = Duration::from_secs(10);

    let len = record_layer
        .read(ContentType::Handshake, timeout)
        .expect("it all went perfectly");
    println!("{}", len);
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
