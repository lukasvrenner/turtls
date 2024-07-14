//! This module provides integers that are larger than what can fit into a regular integer type.
//! This is useful for many algorithms, such as those used in public key cryptography, whose
//! security depends on very large numbers.
use core::ops::{Add, AddAssign, Deref, DerefMut, Div, Mul, Sub, SubAssign};
use core::cmp::{PartialOrd, PartialEq, Ord, Eq, Ordering};

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
/// Internally, it is a little-endian array of 64-bit unsigned integers ([`u64`])
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BigInt<const N: usize>([u64; N]);

impl<const N: usize> BigInt<N> {
    /// Constructs a new `BigInt` of length `N` from a little-endian [`[u64; N`]
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
        for i in 0..N {
            // TODO: use libcore implementation once stabilized
            (diff[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
        (diff.into(), carry)
    }


    /// Returns the number of digits in `self`
    pub fn count_digits(&self) -> usize {
        for (count, digit) in self.iter().rev().enumerate() {
            if *digit != 0 { return N - count };
        }
        N
    }

}

impl<const N: usize> Ord for BigInt<N> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..N).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        return Ordering::Equal;
    }
}

impl <const N: usize> PartialOrd for BigInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn bad_div<const N: usize>(numerat: &[u64], denom: &[u64], out: &mut [u64]) -> [u64; N] {
    let mut quotient = [0u64; N];
    todo!();
}

impl BigInt<4> {
    /// converts a big-endian byte array to a `BigInt`
    // TODO: implement this for all values of `N` once const_generic operations are stabilized
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        // TODO: consider using uninitialized array
        let mut output = [0u64; 4];
        // TODO: use array_chunks once stabilized
        for (chunk, digit) in bytes.rchunks_exact(8).zip(output.iter_mut()) {
            *digit = u64::from_be_bytes(chunk.try_into().unwrap())
        }
        output.into()
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
        for i in 0..N {
            // TODO: use core implementation once stabilized
            (sum[i], carry) = carry_add(self[i], rhs[i], carry);
        }
        sum.into()
    }
}

impl<const N: usize> AddAssign for BigInt<N> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
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
        let mut diff = [0u64; N];
        let mut carry = false;
        for i in 0..N {
            // TODO: use libcore implementation once stabilized
            (diff[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
        diff.into()
    }
}

impl<const N: usize> SubAssign for BigInt<N> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
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
    ///
    /// # Panics
    ///
    /// This function will panic if `rhs == BigInt::ZERO`
    // TODO: make this constant-time
    fn div(self, rhs: Self) -> Self::Output {
        assert_ne!(rhs, BigInt::ZERO);
        // let mut quotient = BigInt::<4>::new([0u64; 4]);
        // while self >= rhs {
        //     quotient = quotient + 1u64.into();
        //     self -= rhs;
        // }
        // // we can safely unwrap because self is now guaranteed to be less than BigInt<4>::MAX
        // (quotient, self.try_into().unwrap())
        todo!();
    }
}

impl Div for BigInt<4> {
    type Output = (Self, Self);
    fn div(self, rhs: Self) -> Self::Output {
        assert_ne!(rhs, BigInt::ZERO);
        // let mut quotient = BigInt::<4>::new([0u64; 4]);
        // while self >= rhs {
        //     quotient = quotient + 1u64.into();
        //     self -= rhs;
        // }
        // // we can safely unwrap because self is now guaranteed to be less than BigInt<4>::MAX
        // (quotient, self.try_into().unwrap())
        todo!();

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
            0xfedcba9876543210,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ]);
        let y = BigInt::from([
            0x0123456789abcdef,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ]);
        assert_eq!(
            x + y,
            BigInt::from([
                0xffffffffffffffff,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ])
        );

        let x = BigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let y = BigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x + y, BigInt::MAX);

        let x = BigInt::from([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(x + y, BigInt::ZERO);
    }

    #[test]
    fn mul() {
        let x = BigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x1000000000000000,
        ]);
        let y = BigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000010000,
            0x0000000000000000,
        ]);
        assert_eq!(
            x * y,
            BigInt::from([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000001000,
                0x0000000000000000,
            ])
        );
    }

    #[test]
    fn div() {
        let x = BigInt::from([0, 0, 0, 1]);
        let y = BigInt::from([0x0123456789abcdef, 0xfedcba9876543211, 0x0123456789abcdef, 0xfedcba9876543211]);
        assert_eq!(y / x, (y, BigInt::ZERO));
    }
}
