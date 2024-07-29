//! This module provides signed and unsigned large integers.
//!
//! This is useful for many algorithms, such as those used in public key cryptography, whose
//! security depends on very large numbers.
//!
//! It contains two types, [`UBigInt`] and [`BigInt`]. Refer to there respective documentation for
//! more information
pub mod unsigned;
pub mod signed;

pub use unsigned::UBigInt;
pub use signed::BigInt;

/// The error that is returned when conversion from a larger [`BigInt`] or [`UBigInt`] to a smaller ['BigInt'] or [`UBigInt`]
/// fails
#[derive(Debug)]
pub struct InputTooLargeError;

impl core::fmt::Display for InputTooLargeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "input is too large for output type")
    }
}

// TODO: uncomment the following line once stabilized
// impl core::error::Error for InputTooLargeError {};
