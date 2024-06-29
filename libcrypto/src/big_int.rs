//! This module provides integers that are larger than what can fit into a regular integer type.
//! This is useful for many algorithms, such as those used in public key cryptography, whose
//! security depends on very large numbers.
use core::ops::{Add, Deref, DerefMut, Div, Mul, Sub};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
/// This structure provides arbitrarily sized unsigned integers.
///
/// Internally, it is a big-endian array of 64-bit unsigned integers ([`u64`])
pub struct BigInt<const N: usize>([u64; N]);

impl<const N: usize> BigInt<N> {
    /// Constructs a new `BigInt` of length `N` from a big-endian [`u64`] array
    pub const fn new(value: [u64; N]) -> Self {
        Self(value)
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

impl<const N: usize> Sub for BigInt<N> {
    type Output = Self;
    /// Overflowing subtraction
    fn sub(self, rhs: Self) -> Self::Output {
        let mut diff = [0u64; N];
        let mut carry = false;
        for i in (0..N).rev() {
            // TODO: use libcore implementation once stabilized
            (diff[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
        diff.into()
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
    fn div(self, rhs: Self) -> Self::Output {
        todo!()
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
