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

use std::ffi::c_int;

use crylib::hash::Sha256;
use crylib::hkdf;
use handshake::handshake_client;

pub use alert::turtls_stringify_alert;
pub use alert::TurtlsAlert;
pub use cipher_suites::TurtlsCipherList;
pub use config::{turtls_get_config, TurtlsConfig};
pub use error::{turtls_get_error, turtls_get_tls_error, TurtlsError};
pub use extensions::app_proto::turtls_app_proto;
pub use extensions::TurtlsExts;
pub use record::TurtlsIo;
use state::ShakeState;
use state::TlsStatus;
pub use state::TurtlsConn;

/// Creates a new connection object.
///
/// The object must be freed by `turtls_free` to avoid memory leakage.
///
/// Lifetime: All pointers contained in `io` must be valid for the lifespan of the connection
/// object.
#[no_mangle]
pub extern "C" fn turtls_new(io: TurtlsIo) -> *mut TurtlsConn {
    Box::leak(TurtlsConn::new(io))
}

/// Frees a connection object.
///
/// After this function is called, `connection` is no longer a valid pointer. Do NOT use it again.
///
/// # Safety:
/// `tls_conn` must be allocated by `turtls_new`.
#[no_mangle]
pub unsafe extern "C" fn turtls_free(tls_conn: *mut TurtlsConn) {
    if tls_conn.is_null() || !tls_conn.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees the pointer is valid.
    let _ = unsafe { Box::from_raw(tls_conn) };
}

/// Performs a TLS handshake with a server, returning the connection status.
///
/// If any error is returned, the connection is automatically closed.
///
/// # Safety:
/// `tls_conn` must be valid.
#[no_mangle]
pub unsafe extern "C" fn turtls_connect(tls_conn: *mut TurtlsConn) -> c_int {
    assert!(!tls_conn.is_null() && tls_conn.is_aligned());

    // SAFETY: the caller guarantees that the pointer is valid.
    let tls_conn = unsafe { &mut *tls_conn };

    loop {
        match tls_conn.state {
            TlsStatus::None => {
                match ShakeState::new(&tls_conn.config) {
                    Ok(state) => tls_conn.state = TlsStatus::Shake(state),
                    Err(err) => {
                        tls_conn.gloabl_state.error.turtls_error = err;
                        return -1;
                    },
                }
                tls_conn.gloabl_state.secret =
                    hkdf::extract::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
                        &[0; Sha256::HASH_SIZE],
                        &[0; Sha256::HASH_SIZE],
                    );
            },
            TlsStatus::Shake(ref mut shake_state) => {
                if let Err(()) =
                    handshake_client(shake_state, &mut tls_conn.gloabl_state, &tls_conn.config)
                {
                    return -1;
                }
                todo!()
            },
            TlsStatus::App { .. } => {
                return 1;
            },
        }
    }
}

/// Alerts the peer and closes the connection.
///
/// # Safety:
/// `tls_conn` must be valid.
#[no_mangle]
pub unsafe extern "C" fn turtls_close(tls_conn: *mut TurtlsConn) {
    if tls_conn.is_null() || !tls_conn.is_aligned() {
        return;
    }
    // SAFETY: the caller guarantees that the pointer is valid.
    let tls_conn = unsafe { &mut *tls_conn };

    if let TlsStatus::None = tls_conn.state {
        return;
    }

    tls_conn.gloabl_state.rl.close_raw(TurtlsAlert::CloseNotify);
    tls_conn.state = TlsStatus::None;
}
