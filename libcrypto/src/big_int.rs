//! This module provides integers that are larger than what can fit into a regular integer type.
//! This is useful for many algorithms, such as those used in public key cryptography, whose
//! security depends on very large numbers.
use core::ops::{Add, Deref, DerefMut, Div, Mul, Sub};

#[derive(Debug)]
pub struct InputTooLargeError;

impl core::fmt::Display for InputTooLargeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "input is too large for output type")
    }
}

// TODO: uncomment the following line once stabilized
// impl core::error::Error for InputTooLargeError {};

/// This structure provides arbitrarily sized unsigned integers.
///
/// Internally, it is a big-endian array of 64-bit unsigned integers ([`u64`])
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BigInt<const N: usize>([u64; N]);

impl<const N: usize> BigInt<N> {
    /// Constructs a new `BigInt` of length `N` from a big-endian [`u64`] array
    pub const fn new(value: [u64; N]) -> Self {
        Self(value)
    }

    /// The zero value of [`BigInt<N>`]
    ///
    /// note: this has the same value as [`BigInt<N>::MIN`]
    pub const ZERO: Self = Self::new([u64::MIN; N]);

    /// The maximum value representable by [`BigInt<N>`]
    pub const MAX: Self = Self::new([u64::MAX; N]);

    /// The minimum value representable by [`BigInt<N>`]
    ///
    /// note: this has the same value as [`BigInt<N>::ZERO`]
    pub const MIN: Self = Self::ZERO;

    /// wrapping-subtracts `rhs` from `self`, returning the result and whether the operation
    /// overflowed
    pub fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let mut diff = [0u64; N];
        let mut carry = false;
        for i in (0..N).rev() {
            // TODO: use libcore implementation once stabilized
            (diff[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
        (diff.into(), carry)
    }
}

impl<const N: usize> Deref for BigInt<N> {
    type Target = [u64; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for BigInt<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<[u64; N]> for BigInt<N> {
    fn from(value: [u64; N]) -> Self {
        Self::new(value)
    }
}

impl<const N: usize> From<BigInt<N>> for [u64; N] {
    fn from(value: BigInt<N>) -> Self {
        value.0
    }
}

impl<const N: usize> From<u64> for BigInt<N> {
    fn from(value: u64) -> Self {
        let mut big_int = [0u64; N];
        big_int[big_int.len() - 1] = value;
        big_int.into()
    }
}

// TODO: make this generic over any size N and O once const generic where clauses are stabilized
impl From<BigInt<4>> for BigInt<8> {
    fn from(value: BigInt<4>) -> Self {
        let mut expanded = [0u64; 8];
        expanded[4..].copy_from_slice(&value.0);
        Self(expanded)
    }
}

// TODO: make this generic over any size N and O once const generic where clauses are stabilized
impl TryFrom<BigInt<8>> for BigInt<4> {
    type Error = InputTooLargeError;
    fn try_from(value: BigInt<8>) -> Result<Self, Self::Error> {
        // we can safely unwrap because the slice is guaranteed to have a length of 4
        if <&[u64] as TryInto<&[u64; 4]>>::try_into(&value[..4]).unwrap() > &[0u64; 4] {
            return Err(InputTooLargeError);
        }
        // we can safely unwrap because the slice is guaranteed to have a length of 4
        Ok(value[4..].try_into().unwrap())
    }
}

impl<const N: usize> TryFrom<&[u64]> for BigInt<N> {
    type Error = core::array::TryFromSliceError;
    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        Ok(<&[u64] as TryInto<[u64; N]>>::try_into(value)?.into())
    }
}

impl<const N: usize> Add for BigInt<N> {
    type Output = Self;
    /// Overflowing addition
    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = [0u64; N];
        let mut carry = false;
        for i in (0..N).rev() {
            // TODO: use core implementation once stabilized
            (sum[i], carry) = carry_add(self[i], rhs[i], carry);
        }
        sum.into()
    }
}

impl<const N: usize> Mul<bool> for BigInt<N> {
    type Output = Self;
    fn mul(self, rhs: bool) -> Self::Output {
        match rhs {
            true => self,
            false => Self::ZERO,
        }
    }
}

impl<const N: usize> Sub for BigInt<N> {
    type Output = Self;
    /// Overflowing subtraction
    fn sub(self, rhs: Self) -> Self::Output {
        self.overflowing_sub(rhs).0
    }
}

impl Mul for BigInt<4> {
    type Output = BigInt<8>;
    /// Performs an expanding multiplication, meaning the output length will be double the input
    /// length
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        let mut product = [0u64; 8];
        for i in 0..self.len() {
            let mut carry = 0;
            for j in 0..rhs.len() {
                (product[i + j], carry) = carry_mul(self[i], rhs[j], carry);
            }
            product[i] = carry;
        }
        product.into()
    }
}

impl Div for BigInt<8> {
    type Output = (BigInt<4>, BigInt<4>);
    /// Returns the quotient and the remainder of the division, in that order
    ///
    /// Warning: this operation is NOT yet constant-time
    // TODO: make this constant-time
    fn div(mut self, rhs: Self) -> Self::Output {
        debug_assert!(self > rhs);
        let mut quotient = BigInt::<4>::new([0u64; 4]);
        while self >= rhs {
            quotient = quotient + 1u64.into();
            self = self - rhs;
        }
        // we can safely unwrap because self is now guaranteed to be less than BigInt<4>::MAX
        (quotient, self.try_into().unwrap())
    }
}

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

    use super::BigInt;

    #[test]
    fn carry_add() {
        let a = 0x0123456789abcdef;
        let b = 0xfedcba9876543210;
        assert_eq!(super::carry_add(a, b, true), (0, true));
    }

    #[test]
    fn add() {
        let x = BigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0xfedcba9876543210,
        ]);
        let y = BigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0123456789abcdef,
        ]);
        assert_eq!(
            x + y,
            BigInt::from([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0xffffffffffffffff,
            ])
        );

        let x = BigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        let y = BigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(x + y, BigInt::MAX);

        let x = BigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543211,
        ]);
        assert_eq!(x + y, BigInt::MIN);
    }
}
