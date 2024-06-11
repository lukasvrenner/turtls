//! This crate implements various cryptographic functions,
//! including AES in GCM and SHA-256.
//!
//! This crate implements these functions purely in software.
//! Hardware implementations are a future goal.
//!
//! WARNING: This code has not been audited. Use at your own risk.
//!
//! This crate has the long-term goal of
//! becoming a fully compliant TLS 1.3 library, with C bindings.
#![warn(missing_docs)]
pub mod aes;
pub mod gcm;
pub mod sha256;
