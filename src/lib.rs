//! A WIP TLS 1.3 library with a C ABI.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]

mod aead;
mod alert;
mod cipher_suites;
mod client_hello;
mod config;
mod extensions;
mod handshake;
mod key_schedule;
mod record;
mod server_hello;
mod state;
mod versions;

use std::time::Duration;

use cipher_suites::GroupKeys;
use client_hello::{CliHelError, ClientHello};
use record::ContentType;
use state::State;

pub use alert::Alert;
pub use cipher_suites::CipherSuites;
pub use config::Config;
pub use record::Io;

#[must_use]
#[repr(C)]
pub enum ShakeResult {
    Ok(Box<State>),
    RngError,
    IoError,
    RecievedAlert(Alert),
    NullPtr,
}

impl From<CliHelError> for ShakeResult {
    fn from(value: CliHelError) -> Self {
        match value {
            CliHelError::IoError => Self::IoError,
            CliHelError::RngError => Self::RngError,
        }
    }
}

/// Generates a default configuration struct.
#[no_mangle]
pub extern "C" fn turtls_generate_config() -> Config {
    Config::default()
}

/// Performs a TLS handshake as the client, returning the connection state or an error.
#[no_mangle]
pub extern "C" fn turtls_client_handshake(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
    config: *const Config,
) -> ShakeResult {
    if config.is_null() {
        return ShakeResult::NullPtr;
    }
    // SAFETY: we just checked to ensure the pointer was non-null.
    let config = unsafe { &*config };

    let mut state = State::new_uninit();

    let record_layer = State::init_record_layer(&mut state, ContentType::Handshake, io);

    let client_hello = ClientHello {
        cipher_suites: &config.cipher_suites,
        extensions: &config.extensions,
    };

    let keys = GroupKeys::generate(config.extensions.sup_groups);

    if let Err(err) = client_hello.write_to(record_layer, &keys) {
        return err.into();
    }

    let len = record_layer
        .read(
            ContentType::Handshake,
            Duration::from_millis(config.timeout_millis),
        )
        .expect("it all went perfectly");
    println!("{}", len);
    todo!();
}

/// Performs a TLS handshake as the server, returning the connection state or an error.
#[no_mangle]
pub extern "C" fn turtls_server_handshake(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
) -> ShakeResult {
    todo!();
}
