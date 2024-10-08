//! This crate has the long-term goal of
//!becoming a fully compliant TLS 1.3 library, with C bindings.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]

use aead::{AeadReader, AeadWriter};

mod aead;
mod alert;
mod cipher_suites;
mod client_hello;
mod extensions;
mod handshake;
mod record;
mod server_hello;
mod versions;

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,
}
