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
#![warn(clippy::cargo)]
#![warn(clippy::nursery)]

#![no_std]

pub mod aes;
pub mod big_int;
pub mod chacha;
pub mod dsa;
pub mod elliptic_curve;
pub mod sha2;
