//! The AES block cipher and GCM AEAD.
//!
//! Generally, AES should not be used on its own. Instead, it should be combined into a
//! higher-level cipher algorithm such as GCM. This module provides GCM support, but others are
//! currently unsupported.
mod aes_core;
pub use aes_core::*;
pub mod gcm;
