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
mod handshake;
mod key_schedule;
mod record;
mod server_hello;
mod state;
mod versions;

pub mod extensions;

use std::{ffi::c_int, time::Duration};

use cipher_suites::GroupKeys;
use client_hello::{CliHelError, ClientHello};
use record::{ContentType, ReadError};
use server_hello::{RecvdSerHello, SerHelParseError};
use state::Connection;

pub use alert::Alert;
pub use cipher_suites::CipherList;
pub use config::Config;
pub use record::Io;

/// The result of the handshake.
#[must_use]
#[repr(C)]
pub enum ShakeResult {
    /// Indicates a successful handshake.
    Ok(*mut Connection),
    /// Indicates that the peer sent an alert.
    RecievedAlert(Alert),
    /// Indicates that there was an error generating a random number.
    RngError,
    /// Indicates that there was an error performing an IO operation.
    IoError,
    /// Indicates that data could not be read within the proper time.
    Timeout,
    /// Indicates that the handshake failed for some unknown reason.
    /// near future.
    HandshakeFailed,
}

impl From<CliHelError> for ShakeResult {
    fn from(value: CliHelError) -> Self {
        match value {
            CliHelError::IoError => Self::IoError,
            CliHelError::RngError => Self::RngError,
        }
    }
}

impl From<SerHelParseError> for ShakeResult {
    fn from(value: SerHelParseError) -> Self {
        match value {
            SerHelParseError::ReadError(err) => Self::from(err),
            SerHelParseError::Failed => Self::HandshakeFailed,
        }
    }
}

impl From<ReadError> for ShakeResult {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::IoError => Self::IoError,
            ReadError::Timeout => Self::Timeout,
            ReadError::RecordOverflow => Self::HandshakeFailed,
            ReadError::UnexpectedMessage => Self::HandshakeFailed,
            ReadError::RecievedAlert(alert) => Self::RecievedAlert(alert),
        }
    }
}

/// Generates a default configuration struct.
#[no_mangle]
pub extern "C" fn turtls_generate_config() -> Config {
    Config::default()
}

/// Performs a TLS handshake as the client, returning the connection state or an error.
///
/// If any error is returned, the connection is automatically closed.
///
/// # Safety:
/// `config` must be valid.
#[no_mangle]
pub unsafe extern "C" fn turtls_client_handshake(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
    config: *const Config,
) -> ShakeResult {
    assert!(!config.is_null() && config.is_aligned());

    // SAFETY: the caller guarantees that the pointer is valid.
    let config = unsafe { &*config };
    let record_timeout = Duration::from_millis(config.timeout_millis);

    let mut state = Box::<Connection>::new_uninit();

    let record_layer = Connection::init_record_layer(&mut state, ContentType::Handshake, io);

    let client_hello = ClientHello {
        cipher_suites: config.cipher_suites,
        extensions: config.extensions,
    };

    let keys = GroupKeys::generate(config.extensions.sup_groups);

    if let Err(err) = client_hello.write_to(record_layer, &keys) {
        return err.into();
    }

    let server_hello = match RecvdSerHello::read(record_layer, record_timeout) {
        Ok(server_hello) => server_hello,
        Err(err) => return err.into(),
    };
    todo!();
}

/// Alerts the peer, closes the connection, and frees the allocation.
///
/// If `connection` is `NULL`, nothing happens.
///
/// # Safety:
/// If `connection` isn't `NULL`, `connection` must be valid and recieved from the handshake.
#[no_mangle]
pub unsafe extern "C" fn turtls_close(connection: *mut Connection) {
    if connection.is_null() || !connection.is_aligned() {
        return;
    }

    // SAFETY: the caller guarantees that the pointer is valid.
    // `state` was allocated with `Box`.
    let mut state = unsafe { Box::from_raw(connection) };

    state.record_layer.alert_and_close(Alert::CloseNotify);

    // `state` dropped here.
}
