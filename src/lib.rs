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
mod error;
mod extensions;
mod handshake;
mod key_schedule;
mod record;
mod server_hello;
mod state;

use core::panic;
use std::time::Duration;

use crylib::hash::Sha256;
use crylib::hkdf;

use client_hello::ClientHello;
use error::TlsError;
use extensions::key_share::GroupKeys;
use handshake::MsgBuf;
use record::{ContentType, ReadError, RecordLayer};

pub use alert::turtls_stringify_alert;
pub use alert::Alert;
pub use cipher_suites::CipherList;
pub use config::{Config, ConfigError};
pub use error::ShakeResult;
pub use extensions::app_proto::turtls_app_proto;
pub use extensions::ExtList;
pub use record::Io;
pub use state::Connection;
use state::{RlState, ShakeState};

/// Generates a default configuration struct.
#[no_mangle]
pub extern "C" fn turtls_generate_config() -> Config {
    Config::default()
}

/// Allocates a connection buffer.
///
/// This buffer must be freed by `turtls_free` to avoid memory leakage.
#[no_mangle]
pub extern "C" fn turtls_alloc() -> *mut Connection {
    Box::leak(Connection::new())
}

/// Frees a connection buffer.
///
/// After this function is called, `connection` is no longer a valid pointer. Do NOT use it again.
///
/// # Safety:
/// `connection` must be allocated by `turtls_alloc`.
#[no_mangle]
pub unsafe extern "C" fn turtls_free(connection: *mut Connection) {
    if connection.is_null() || !connection.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees the pointer is valid.
    let _ = unsafe { Box::from_raw(connection) };
}

/// Performs a TLS handshake with a server, returning the connection status.
///
/// If any error is returned, the connection is automatically closed.
///
/// # Safety:
/// `connection` must be valid.
/// `config` must be valid, as well as all of the pointers it stores.
///
/// Lifetime: `io.ctx` must be valid until the connction is closed.
#[no_mangle]
pub unsafe extern "C" fn turtls_connect(
    // TODO: use c_size_t and c_ssize_t once stabilized
    io: Io,
    connection: *mut Connection,
    config: *const Config,
) -> ShakeResult {
    assert!(!config.is_null() && config.is_aligned());
    assert!(!connection.is_null() && connection.is_aligned());

    // SAFETY: the caller guarantees that the pointer is valid.
    let connection = unsafe { &mut *connection };

    // SAFETY: the caller guarantees that the pointer is valid.
    let config = unsafe { &*config };
    let record_timeout = Duration::from_millis(config.timeout_millis);

    let priv_keys = match GroupKeys::generate(config.extensions.sup_groups) {
        Ok(keys) => keys,
        Err(err) => return err.into(),
    };
    let client_hello = ClientHello {
        cipher_suites: config.cipher_suites,
        extensions: config.extensions,
    };

    // TODO: is this precomputed at compile time?
    let early_secret = hkdf::extract::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
        &[0; Sha256::HASH_SIZE],
        &[0; Sha256::HASH_SIZE],
    );

    connection.rl = Some(RecordLayer::new(io, record_timeout));
    let rl = connection.rl.as_mut().unwrap();

    if let Err(err) = client_hello.write_to(rl, &priv_keys) {
        rl.close(Alert::InternalError);
        connection.rl = None;
        return err.into();
    }

    let mut shake_state = ShakeState {
        rl_state: RlState {
            secret: early_secret,
            priv_keys,
            ciphers: config.cipher_suites,
            sup_groups: config.extensions.sig_algs,
            sig_algs: config.extensions.sig_algs,
            rl,
        },
        msg_buf: MsgBuf::new(0x20000),
    };

    if let Err(err) = server_hello::read_and_parse(&mut shake_state) {
        match err {
            ReadError::Alert(TlsError::Sent(alert)) => {
                rl.close(alert);
                connection.rl = None;
                return ShakeResult::SentAlert(alert);
            },
            _ => {
                connection.rl = None;
                return err.into();
            },
        }
    }
    //
    //if let Err(err) = rl.read() {
    //    if let ReadError::Alert(TlsError::Sent(alert)) = err {
    //        rl.close(alert);
    //    }
    //    return err.into();
    //}
    //
    //if rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
    //    if let Err(err) = rl.read() {
    //        if let ReadError::Alert(TlsError::Sent(alert)) = err {
    //            rl.close(alert);
    //        }
    //        return err.into();
    //    }
    //}
    if let Err(err) = shake_state.read() {
        match err {
            ReadError::Alert(TlsError::Sent(alert)) => {
                rl.close(alert);
                connection.rl = None;
                return ShakeResult::SentAlert(alert);
            },
            _ => {
                connection.rl = None;
                return err.into();
            },
        }
    }
    todo!("finish handshake");
}

/// Alerts the peer and closes the connection.
///
/// # Safety:
/// `connection` must be valid.
#[no_mangle]
pub unsafe extern "C" fn turtls_close(connection: *mut Connection) {
    if connection.is_null() || !connection.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees that the pointer is valid.
    let connection = unsafe { &mut *connection };

    if let Some(ref mut rl) = connection.rl {
        rl.close(Alert::CloseNotify);
    }
    connection.rl = None;
}
