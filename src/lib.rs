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

use handshake::handshake_client;
use handshake::ShakeBuf;

pub use alert::turtls_stringify_alert;
pub use alert::Alert;
pub use cipher_suites::CipherList;
pub use config::turtls_set_server_name;
pub use error::ShakeResult;
pub use extensions::app_proto::turtls_app_proto;
pub use extensions::ExtList;
pub use record::Io;
pub use state::Connection;
use state::ShakeState;
use state::TlsStatus;

/// Creates a new connection object.
///
/// The object must be freed by `turtls_free` to avoid memory leakage.
///
/// Lifetime: All pointers contained in `io` must be valid for the lifespan of the connection
/// object.
#[no_mangle]
pub extern "C" fn turtls_new(io: Io) -> *mut Connection {
    Box::leak(Connection::new(io))
}

/// Frees a connection buffer.
///
/// After this function is called, `connection` is no longer a valid pointer. Do NOT use it again.
///
/// # Safety:
/// `connection` must be allocated by `turtls_new`.
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
#[no_mangle]
pub unsafe extern "C" fn turtls_connect(connection: *mut Connection) -> ShakeResult {
    assert!(!connection.is_null() && connection.is_aligned());

    // SAFETY: the caller guarantees that the pointer is valid.
    let connection = unsafe { &mut *connection };

    loop {
        match connection.status {
            TlsStatus::None => match ShakeState::new(&connection.config) {
                Ok(state) => connection.status = TlsStatus::Shake(state),
                Err(err) => return err.into(),
            },
            TlsStatus::Shake(ref mut shake_state) => {
                handshake_client(shake_state, &mut connection.state, &connection.config);
                todo!()
            },
            TlsStatus::App => {
                todo!()
            },
        }
    }
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

    if let TlsStatus::None = connection.status {
        return;
    }

    connection.state.rl.close(Alert::CloseNotify);
    connection.status = TlsStatus::None;
}
