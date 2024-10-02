//! This crate has the long-term goal of
//!becoming a fully compliant TLS 1.3 library, with C bindings.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]

pub mod client;
mod handshake;
pub mod server;

#[repr(C)]
pub struct Message {
    pub ptr: *const u8,
    pub len: usize,
}
