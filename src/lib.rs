//! This crate has the long-term goal of
//!becoming a fully compliant TLS 1.3 library, with C bindings.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]

mod aead;
mod cipher_suites;
mod client_hello;
mod extensions;
mod handshake;
mod record;
mod server_hello;

const LEGACY_PROTO_VERS: [u8; 2] = [0x03, 0x03];

pub struct State {
    read_nonce: u64,
    write_nonce: u64,
}
