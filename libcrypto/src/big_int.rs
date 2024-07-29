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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputTooLargeError;

impl core::fmt::Display for InputTooLargeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "input is too large for output type")
    }
}

// TODO: uncomment the following line once stabilized
// impl core::error::Error for InputTooLargeError {};

const fn carry_add(x: u64, y: u64, carry: bool) -> (u64, bool) {
    let (sum1, overflowed1) = x.overflowing_add(y);
    let (sum2, overflowed2) = sum1.overflowing_add(carry as u64);
    (sum2, overflowed1 || overflowed2)
}

const fn carry_mul(x: u64, y: u64, carry: u64) -> (u64, u64) {
    let product = x as u128 * y as u128 + carry as u128;
    (product as u64, (product >> 64) as u64)
}

const fn carry_sub(x: u64, y: u64, carry: bool) -> (u64, bool) {
    let (diff1, overflowed1) = x.overflowing_sub(y);
    let (diff2, overflowed2) = diff1.overflowing_sub(carry as u64);
    (diff2, overflowed1 || overflowed2)
}

#[cfg(test)]
mod tests {
    #[test]
    fn carry_add() {
        let a = 0x0123456789abcdef;
        let b = 0xfedcba9876543210;
        assert_eq!(super::carry_add(a, b, true), (0, true));
    }

    #[test]
    fn carry_sub() {
        let a = 0;
        let b = 0xfedcba9876543210;
        assert_eq!(super::carry_sub(a, b, true), (0x0123456789abcdef, true));
    }
}
