//! This crate has the long-term goal of
//!becoming a fully compliant TLS 1.3 library, with C bindings.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]

mod aead;
mod alert;
mod cipher_suites;
mod client_hello;
mod extensions;
mod handshake;
mod key_schedule;
mod record;
mod server_hello;
mod versions;

use aead::{AeadReader, AeadWriter};
use cipher_suites::GroupKeys;
pub use handshake::shake_hands;

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,

    group_keys: GroupKeys,
}
