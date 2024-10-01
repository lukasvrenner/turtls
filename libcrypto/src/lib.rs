//! A collection of cryptographic primitives.
//!
//! <div class="warning">
//! WARNING: This code has not been audited. Use it at your own risk.
//! </div>
//#![warn(missing_docs, clippy::cargo)]
#![warn(clippy::cargo)]
#![no_std]

pub mod aes;
pub mod big_int;
pub mod chacha;
pub mod ec;
pub mod finite_field;
pub mod sha2;
