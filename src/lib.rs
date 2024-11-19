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
mod init;
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
use init::TagUninit;
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
    Box::leak(Box::new(Connection(TagUninit::new_uninit())))
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
    let config = unsafe { &*config };
    let record_timeout = Duration::from_millis(config.timeout_millis);

    let connection = unsafe { &mut *connection };

    let state = connection.0.deinit();

    let record_layer = State::init_record_layer(state, ContentType::Handshake, io);

    let client_hello = ClientHello {
        cipher_suites: config.cipher_suites,
        extensions: config.extensions,
    };

    let keys = match GroupKeys::generate(config.extensions.sup_groups) {
        Ok(keys) => keys,
        Err(err) => return err.into(),
    };

    // TODO: is this precomputed at compile time?
    let early_secret = hkdf::extract::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
        &[0; Sha256::HASH_SIZE],
        &[0; Sha256::HASH_SIZE],
    );

    if let Err(err) = client_hello.write_to(record_layer, &keys) {
        return err.into();
    }

    let server_hello = match RecvdSerHello::read(record_layer, record_timeout) {
        Ok(server_hello) => server_hello,
        Err(err) => {
            if let ReadError::TlsError(TlsError::Alert(alert)) = err {
                record_layer.alert_and_close(alert);
            }
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
            record_layer.alert_and_close(err);
            return ShakeResult::PeerError(err);
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
    let transcript = record_layer.transcript();
    let cli_shake_traf_secret =
        key_schedule::derive_secret(&handshake_secret, b"c hs traffic", &transcript);
    let ser_shake_traf_secret =
        key_schedule::derive_secret(&handshake_secret, b"s hs traffic", &transcript);

    let handsake_aead = TlsAead::new(&cli_shake_traf_secret, &ser_shake_traf_secret, cipher_suite);

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

    if let Some(_state) = connection.0.get_mut() {
        todo!("send encrypted CloseNotify alert");
    }
}
