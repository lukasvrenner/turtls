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
mod dh;
mod handshake;
mod key_schedule;
mod record;
mod server_hello;
mod versions;

pub mod error;
pub mod extensions;

use std::time::Duration;

use aead::TlsAead;
use client_hello::ClientHello;
use crylib::{
    hash::{Hasher, Sha256},
    hkdf,
};
use dh::{GroupKeys, NamedGroup};
use error::TlsError;
use extensions::SECP256R1;
use record::{ContentType, ReadError, RecordLayer};
use server_hello::SerHelloRef;

pub use alert::Alert;
pub use cipher_suites::CipherList;
pub use config::{Config, ConfigError};
pub use error::ShakeResult;
pub use record::Io;
pub use alert::turtls_stringify_alert;

/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection(Option<RecordLayer>);

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
    Box::leak(Box::new(Connection(None)))
}

/// Frees a connection buffer.
///
/// This buffer must have been allocated by `turtls_alloc`.
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
/// `config` must be valid.
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

    *connection = Connection(Some(RecordLayer::new(io, record_timeout)));
    let rl = connection.0.as_mut().unwrap();

    if let Err(err) = client_hello.write_to(rl, &priv_keys) {
        rl.close(Alert::InternalError);
        *connection = Connection(None);
        return err.into();
    }

    let server_hello = match SerHelloRef::read_and_parse(rl) {
        Ok(server_hello) => server_hello,
        Err(err) => {
            if let ReadError::Alert(TlsError::Sent(alert)) = err {
                rl.close(alert);
            }
            *connection = Connection(None);
            return err.into();
        },
    };

    let cipher_suite = CipherList {
        suites: server_hello.cipher_suite.suites & config.cipher_suites.suites,
    };

    let salt = key_schedule::derive_secret(&early_secret, b"derived", &Sha256::hash(b""));
    let handshake_secret = match server_hello.key_share_type {
        x if x == NamedGroup::Secp256r1.to_be_bytes()
            && config.extensions.sup_groups & SECP256R1 > 0 =>
        {
            let Some(dh_shared_secret) =
                dh::secp256r1_shared_secret(server_hello.key_share, &priv_keys)
            else {
                rl.close(Alert::IllegalParam);
                *connection = Connection(None);
                return ShakeResult::SentAlert(Alert::IllegalParam);
            };
            hkdf::extract::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
                &salt,
                &dh_shared_secret,
            )
        },
        _ => {
            rl.close(Alert::HandshakeFailure);
            *connection = Connection(None);
            return ShakeResult::SentAlert(Alert::HandshakeFailure);
        },
    };
    let transcript = rl.transcript();
    let cli_shake_traf_secret =
        key_schedule::derive_secret(&handshake_secret, b"c hs traffic", &transcript);
    let ser_shake_traf_secret =
        key_schedule::derive_secret(&handshake_secret, b"s hs traffic", &transcript);

    rl.aead = TlsAead::new(&cli_shake_traf_secret, &ser_shake_traf_secret, cipher_suite);
    if rl.aead.is_none() {
        rl.close(Alert::HandshakeFailure);
        *connection = Connection(None);
        return ShakeResult::SentAlert(Alert::HandshakeFailure);
    }

    if let Err(err) = rl.read() {
        if let ReadError::Alert(TlsError::Sent(alert)) = err {
            rl.close(alert);
        }
        return err.into();
    }

    if rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
        if let Err(err) = rl.read() {
            if let ReadError::Alert(TlsError::Sent(alert)) = err {
                rl.close(alert);
            }
            return err.into();
        }
    }
    todo!("finish handshake");
}

/// Alerts the peer and closes the connection.
///
/// # Safety:
/// `connection` may be `NULL` but must be valid.
#[no_mangle]
pub unsafe extern "C" fn turtls_close(connection: *mut Connection) {
    if connection.is_null() || !connection.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees that the pointer is valid.
    let connection = unsafe { &mut *connection };

    if let Some(ref mut rl) = connection.0 {
        rl.close(Alert::CloseNotify);
        *connection = Connection(None);
    }
}
