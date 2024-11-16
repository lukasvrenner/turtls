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

use std::mem::MaybeUninit;
use std::time::Duration;

use cipher_suites::GroupKeys;
use client_hello::{CliHelError, ClientHello};
use record::{ContentType, ReadError};
use server_hello::{RecvdSerHello, SerHelParseError};
use state::{State, Connection};

pub use alert::Alert;
pub use cipher_suites::CipherList;
pub use config::Config;
pub use record::Io;

/// The result of the handshake.
#[must_use]
#[repr(C)]
pub enum ShakeResult {
    /// Indicates a successful handshake.
    Ok,
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
    /// Indicates that a handshake message was not able to be decoded.
    DecodeError,
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
            SerHelParseError::DecodeError => Self::DecodeError,
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

/// Allocates a connection buffer.
///
/// This buffer must be freed by `turtls_free` to avoid memory leakage.
#[allow(private_interfaces)]
#[no_mangle]
pub extern "C" fn turtls_alloc() -> *mut Connection {
    Box::leak(Box::new(Connection::Uninit(MaybeUninit::uninit())))
}

/// Frees a connection buffer.
///
/// This buffer must have been allocated by `turtls_alloc`.
///
/// # Safety:
/// `connection` must be allocated by `turtls_alloc`
#[allow(private_interfaces)]
#[no_mangle]
pub unsafe extern "C" fn turtls_free(connection: *mut Connection) {
    if connection.is_null() || !connection.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees the pointer is valid.
    let _ = unsafe { Box::from_raw(connection) };
}

/// Performs a TLS handshake as the client, returning the handshake status.
///
/// If any error is returned, the connection is automatically closed.
///
/// # Safety:
/// `config` must be valid.
/// `connection` must be valid.
#[allow(private_interfaces)]
#[no_mangle]
pub unsafe extern "C" fn turtls_client_handshake(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
    connection: *mut Connection,
    config: *const Config,
) -> ShakeResult {
    assert!(!config.is_null() && config.is_aligned());
    assert!(!connection.is_null() && connection.is_aligned());

    // SAFETY: the caller guarantees that the pointer is valid.
    let config = unsafe { &*config };
    let record_timeout = Duration::from_millis(config.timeout_millis);

    let connection = unsafe { &mut *connection };

    *connection = Connection::Uninit(MaybeUninit::uninit());
    let state = match connection {
        Connection::Uninit(ref mut state) => state,
        Connection::Init(_) => unreachable!(),
    };

    let record_layer = State::init_record_layer(state, ContentType::Handshake, io);

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
    todo!("finish handshake");
}

/// Alerts the peer and closes the connection.
///
/// # Safety:
/// `connection` may be `NULL` but must be valid.
#[allow(private_interfaces)]
#[no_mangle]
pub unsafe extern "C" fn turtls_close(connection: *mut Connection) {
    if connection.is_null() || !connection.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees that the pointer is valid.
    let connection = unsafe { &mut *connection };

    if let Connection::Init(ref mut state) = connection {
        state.record_layer.alert_and_close(Alert::CloseNotify);
    }
}
