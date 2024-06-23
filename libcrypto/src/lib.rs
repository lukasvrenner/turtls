//! This crate implements various cryptographic functions,
//! including AES in GCM and SHA-256.
//!
//! This crate implements these functions purely in software.
//! Hardware implementations are a future goal.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use at your own risk.
//! </div>
#![warn(missing_docs)]
pub mod aes;
pub mod chacha;
pub mod dsa;
pub mod sha2;
pub mod big_int;
