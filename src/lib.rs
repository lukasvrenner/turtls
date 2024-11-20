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
mod state;
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
use dh::GroupKeys;
use error::TlsError;
use extensions::KeyShare;
use record::{ContentType, ReadError};
use server_hello::RecvdSerHello;
use state::{Connection, State};

pub use alert::Alert;
pub use cipher_suites::CipherList;
pub use config::{Config, ConfigError};
pub use error::ShakeResult;
pub use record::Io;

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

/// Performs a TLS handshake as the client, returning the handshake status.
///
/// If any error is returned, the connection is automatically closed.
///
/// # Safety:
/// `config` must be valid.
/// `connection` must be valid.
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
    let connection = unsafe { &mut *connection };

    // SAFETY: the caller guarantees that the pointer is valid.
    let config = unsafe { &*config };
    let record_timeout = Duration::from_millis(config.timeout_millis);

    let keys = match GroupKeys::generate(config.extensions.sup_groups) {
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

    *connection = Connection(Some(State::new(io)));
    let state = connection.0.as_mut().expect("connection state exists");

    if let Err(err) = client_hello.write_to(&mut state.rl.unenc_rl, &keys) {
        // don't alert because we haven't even sent ClientHello
        return err.into();
    }

    let server_hello = match RecvdSerHello::read(&mut state.rl.unenc_rl, record_timeout) {
        Ok(server_hello) => server_hello,
        Err(err) => {
            if let ReadError::Alert(TlsError::Sent(alert)) = err {
                state.rl.unenc_rl.alert_and_close(alert);
            }
            *connection = Connection(None);
            return err.into();
        },
    };

    let dh_shared_secret = match KeyShare::parse_ser(
        server_hello.extensions.key_share,
        config.extensions.sup_groups,
        &keys,
    ) {
        Ok(secret) => secret,
        Err(err) => {
            state.rl.unenc_rl.alert_and_close(err);
            *connection = Connection(None);
            return ShakeResult::SentAlert(err);
        },
    };
    let cipher_suite = CipherList {
        suites: server_hello.cipher_suite.suites & config.cipher_suites.suites,
    };

    let salt = key_schedule::derive_secret(&early_secret, b"derived", &Sha256::hash(b""));
    let handshake_secret = hkdf::extract::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
        &salt,
        &dh_shared_secret,
    );
    let transcript = state.rl.unenc_rl.transcript();
    let cli_shake_traf_secret =
        key_schedule::derive_secret(&handshake_secret, b"c hs traffic", &transcript);
    let ser_shake_traf_secret =
        key_schedule::derive_secret(&handshake_secret, b"s hs traffic", &transcript);

    state.rl.aead = match TlsAead::new(&cli_shake_traf_secret, &ser_shake_traf_secret, cipher_suite)
    {
        Some(aead) => aead,
        None => {
            state.rl.unenc_rl.alert_and_close(Alert::HandshakeFailure);
            *connection = Connection(None);
            return ShakeResult::SentAlert(Alert::HandshakeFailure);
        },
    };
    let mut msg_type = match state.rl.unenc_rl.read(record_timeout) {
        Ok(msg_type) => msg_type,
        Err(err) => {
            if let ReadError::Alert(TlsError::Sent(alert)) = err {
                state.rl.alert_and_close(alert);
            }
            return err.into();
        },
    };
    if msg_type == ContentType::ChangeCipherSpec.to_byte() {
        msg_type = match state.rl.unenc_rl.read(record_timeout) {
            Ok(msg_type) => msg_type,
            Err(err) => {
                if let ReadError::Alert(TlsError::Sent(alert)) = err {
                    state.rl.alert_and_close(alert);
                }
                *connection = Connection(None);
                return err.into();
            },
        }
    }
    if msg_type != ContentType::ApplicationData.to_byte() {
        println!("{msg_type}");
        state.rl.alert_and_close(Alert::UnexpectedMessage);
        *connection = Connection(None);
        return ShakeResult::SentAlert(Alert::UnexpectedMessage);
    }
    state.rl.decrypt().expect("decryption went well");
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

    if let Some(ref mut state) = connection.0 {
        state.rl.alert_and_close(Alert::CloseNotify);
        *connection = Connection(None);
    }
}
