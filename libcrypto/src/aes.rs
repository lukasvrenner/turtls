//! This module provides cryptographic primitives for AES and AES-GCM
//!
//! AES should not be used on its own. Instead, it should be combined with a mode of operation,
//! such as CTR or CBC. Usually it is even more preferable to use an AEAD (Authenticated Encryption
//! with Associated Data) for authenticated encryption. This module provides one such algorithm,
//! GCM (Galois/Counter Mode).
mod aes_core;
pub use aes_core::*;
mod gcm;
