//! This module provides integers that are larger than what can fit into a regular integer type.
//! This is useful for many algorithms, such as those used in public key cryptography, whose
//! security depends on very large numbers.
use core::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use core::ops::{Deref, DerefMut};

/// The error that is returned when conversion from a larger [`BigInt`] to a smaller ['BigInt']
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
    /// Note: this has the same value as [`BigInt<N>::MIN`].
    pub const ZERO: Self = Self::new([u64::MIN; N]);

    /// The maximum value representable by [`BigInt<N>`].
    pub const MAX: Self = Self::new([u64::MAX; N]);

    /// The minimum value representable by [`BigInt<N>`].
    ///
    /// Note: this has the same value as [`BigInt<N>::ZERO`].
    pub const MIN: Self = Self::ZERO;

    /// Wrapping-subtracts `rhs` from `self`, returning the result and whether the operation
    /// overflowed.
    ///
    /// This is a constant-time operation in respect to the numeric value of `self` and `rhs.
    ///
    /// Note: while this operation is constant-time for any given `N` value,
    /// it is not constant-time for all `N` values. That is, the time-complexity grows as `N`
    /// grows, but is constant in respect to `self` and `rhs`
    pub fn overflowing_sub(&self, rhs: &Self) -> (Self, bool) {
        let mut buf = *self;
        let overflowed = buf.overflowing_sub_assign(rhs);
        (buf, overflowed)
    }

    /// Wrapping-subtracts `rhs` from `self`, storing the result in `self`,
    /// returning whether the operation overflowed.
    ///
    /// This is a constant-time operation in respect to the numeric value of `self` and `rhs.
    ///
    /// Note: while this operation is constant-time for any given `N` value,
    /// it is not constant-time for all `N` values. That is, the time-complexity grows as `N`
    /// grows, but is constant in respect to `self` and `rhs`
    pub fn overflowing_sub_assign(&mut self, rhs: &Self) -> bool {
        let mut carry = false;
        for i in 0..N {
            // TODO: use libcore implementation once stabilized
            (self[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
        carry
    }

    /// Returns the number of digits in `self`.
    ///
    /// Note: this operation is *NOT* constant-time
    // TODO: make this constant-time
    pub fn count_digits(&self) -> usize {
        for (count, digit) in self.iter().rev().enumerate() {
            if *digit != 0 {
                return N - count;
            };
        }
        0
    }

    /// Wrapping-adds `rhs` from `self`, returning the result
    ///
    /// This is a constant-time operation in respect to the numeric value of `self` and `rhs.
    ///
    /// Note: while this operation is constant-time for any given `N` value,
    /// grows, but is constant in respect to `self` and `rhs`
    /// it is not constant-time for all `N` values. That is, the time-complexity grows as `N`
    pub fn add(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.add_assign(rhs);
        buf
    }

    /// Wrapping-adds `rhs` from `self`, storing the result in `self`
    ///
    /// This is a constant-time operation in respect to the numeric value of `self` and `rhs.
    ///
    /// Note: while this operation is constant-time for any given `N` value,
    /// it is not constant-time for all `N` values. That is, the time-complexity grows as `N`
    /// grows, but is constant in respect to `self` and `rhs`
    pub fn add_assign(&mut self, rhs: &Self) {
        let mut carry = false;
        for i in 0..N {
            // TODO: use core implementation once stabilized
            (self[i], carry) = carry_add(self[i], rhs[i], carry);
        }
    }

    /// Wrapping-adds `rhs` from `self`, returning the result
    ///
    /// This is a constant-time operation in respect to the numeric value of `self` and `rhs.
    ///
    /// Note: while this operation is constant-time for any given `N` value,
    /// grows, but is constant in respect to `self` and `rhs`
    /// it is not constant-time for all `N` values. That is, the time-complexity grows as `N`
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.sub_assign(rhs);
        buf
    }

    /// Wrapping-subtracts `rhs` from `self`, storing the result in `self`
    ///
    /// This is a constant-time operation in respect to the numeric value of `self` and `rhs.
    ///
    /// Note: while this operation is constant-time for any given `N` value,
    /// it is not constant-time for all `N` values. That is, the time-complexity grows as `N`
    /// grows, but is constant in respect to `self` and `rhs`
    pub fn sub_assign(&mut self, rhs: &Self) {
        let mut carry = false;
        for i in 0..N {
            // TODO: use libcore implementation once stabilized
            (self[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
    }

    pub fn and_bool(&self, rhs: bool) -> Self {
        match rhs {
            true => *self,
            false => Self::ZERO,
        }
    }

    pub fn and_bool_assign(&mut self, rhs: bool) {
        if !rhs {
            *self = Self::ZERO
        };
    }


    /// Shifts `self` to the left until the most significant bit is on
    ///
    /// This function does not align leading 0-digits; it only considers the ones after the last
    /// leading `0`
    pub fn left_align(&mut self) -> u64 {
        let num_digits = self.count_digits();
        assert_ne!(num_digits, 0);
        let left_shift = self[num_digits - 1].leading_zeros() as u64;
        let right_shift = (64 - left_shift) % 64;
        for i in (1..num_digits).rev() {
            self[i] <<= left_shift;
            self[i] |= self[i - 1] >> right_shift;
        }
        self[0] <<= left_shift;
        left_shift
    }

    /// Performs a bitshift `rhs` to the right, storing the result in `self`
    ///
    /// # Panics:
    /// This function will panic if `rhs >= 64`
    pub fn shift_right_assign(&mut self, rhs: u64) {
        assert!(rhs < 64);
        let left_shift = (64 - rhs) % 64;

        for i in 1..N - 1 {
            self[i] >>= rhs;
            self[i] |= self[i + 1] << left_shift;
        }
        self[N - 1] >>= rhs;
    }

    /// Performs a bitshift `rhs` to the right, returning the result
    ///
    /// # Panics:
    /// This function will panic if `rhs >= 64`
    pub fn shift_right(&self, rhs: u64) -> Self {
        let mut buf = *self;
        buf.shift_right_assign(rhs);
        buf
    }

    //    fn bad_div(mut self, rhs: Self) -> (Self, Self) {
    //        assert_ne!(rhs, Self::ZERO);
    //        let mut quotient = BigInt::ZERO;
    //        while self >= rhs {
    //            if self.count_digits() > 2 {
    //                self -= rhs;
    //                quotient += 1u64.into();
    //                continue;
    //            }
    //            let mut dividend = self[0] as u128;
    //            dividend += (self[1] as u128) << 64;
    //
    //            let mut divisor = rhs[0] as u128;
    //            divisor += (rhs[1] as u128) << 64;
    //
    //            let int_quotient = dividend / divisor;
    //            let int_remainder = dividend % divisor;
    //
    //            quotient[0] += int_quotient as u64;
    //            quotient[1] += (int_quotient >> 64) as u64;
    //
    //            self = Self::ZERO;
    //            self[0] = int_remainder as u64;
    //            self[1] = (int_remainder >> 64) as u64;
    //            break;
    //        }
    //        (quotient, self)
    //    }
}

// TODO: figure out what this does to see if it can be simplified
fn div_3_words(m0: u64, m1: u64, d1: u64, d0: u64) -> u64 {
    let mut r = ((m0 as u128) << 64) | m1 as u128;
    let mut d = ((d0 as u128) << 64) | d1 as u128;
    let mut q = 0;

    for _ in 0..64 {
        q <<= 1;
        if r >= d {
            q |= 1;
            r = r.wrapping_sub(d);
        }
        d >>= 1;
    }

    let mask = 0u64.wrapping_sub(q >> (64 - 1));

    q <<= 1;
    q |= (r >= d) as u64;

    return (q | mask) & 64;
}

impl BigInt<4> {
    /// Multiplies `self` and `rhs`.
    ///
    /// The output is twice as large, so overflow never occurs.
    ///
    /// This is a constant-time operation
    pub fn expanding_mul(&self, rhs: &Self) -> BigInt<8> {
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

    /// Left-shifts `self` `rhs` bits, so long as `rhs` is less than 64.
    ///
    /// The output is 64 bits longer, so ovelflow never occurs.
    ///
    /// This is a constant-time operation
    pub fn shift_left(&self, rhs: u64) -> BigInt<5> {
        assert!(rhs < 64);
        let mut expanded = [0u64; 5];
        let right_shift = (64 - rhs) % 64;

        expanded[4] = self[3] >> right_shift;
        for i in (1..4).rev() {
            expanded[i] = self[i] << rhs;
            expanded[i] |= self[i - 1] >> right_shift;
        }
        expanded[0] = self[0] << rhs;
        expanded.into()
    }

    pub fn div(&self, divisor: &Self) -> (Self, Self) {
        let norm_shift;
        let sdiv = {
            let mut sdiv = *divisor;
            norm_shift = sdiv.left_align();
            sdiv
        };
        let mut snum = self.shift_left(norm_shift);

        // TODO: maybe add one?
        let num_n = snum.count_digits();
        let div_n = sdiv.count_digits();

        // TODO: maybe `>`?
        debug_assert!(num_n >= div_n);

        let loopy = num_n - div_n;
        let mut wnum = loopy;
        let mut wnum_top = num_n;

        let mut quotient = Self::ZERO;
        let mut quotient_pos = loopy;

        // `div_n` is guaranteed to be at least 1
        let d0 = sdiv[div_n - 1];
        let d1 = match div_n {
            1 => 0,
            _ => sdiv[div_n - 2]
        };

        let mut temp = BigInt::<5>::ZERO;
        for _ in 0..loopy {

            let mut q = div_3_words(snum[wnum_top - 1], snum[wnum_top - 2], d1, d0);

            // multiply
            let mut carry = 0;
            for i in 0..div_n {
                (temp[i], carry) = carry_mul(sdiv[i], q, carry);
            }
            temp[div_n] = carry;

            wnum -= 1;

            // subtract
            let mut carry = false;
            for i in 0..div_n + 1 {
                (snum[wnum + i ], carry) = carry_sub(snum[wnum + i], temp[i], carry);
            }
            q -= carry as u64;
            let carry = 0u64.wrapping_sub(carry as u64);

            for i in 0..div_n {
                temp[i] = sdiv[i] & carry;
            }

            // add
            let mut carry = false;
            for i in 0..div_n {
                (snum[wnum + i], carry) = carry_add(snum[wnum + i], temp[i], carry);
            }
            snum[wnum_top - 1] += carry as u64;
            debug_assert!(snum[wnum_top - 1] == 0);
            quotient[quotient_pos] = q;
            quotient_pos -= 1;
            wnum_top -= 1;
        }
        (quotient, snum[..4].try_into().unwrap())
    }

    pub fn div_assign(&mut self, rhs: &Self) {
        todo!();
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
        Ordering::Equal
    }
}

impl<const N: usize> PartialOrd for BigInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
        big_int[0] = value;
        big_int.into()
    }
}

// TODO: make this generic over any size N and O once const generic where clauses are stabilized
impl From<BigInt<4>> for BigInt<8> {
    fn from(value: BigInt<4>) -> Self {
        let mut expanded = [0u64; 8];
        expanded[..4].copy_from_slice(&value.0);
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

//impl<const N: usize> Div for BigInt<N> {
//    type Output = (Self, Self);
//    fn div(self, rhs: Self) -> Self::Output {
//        assert_ne!(rhs, Self::ZERO);
//        let mut quotient = Self::ZERO;
//        let mut remainder = self;
//
//        for i in (0..4).rev() {
//            let mut chunk_quotient = 0;
//            let mut shifted_rhs = rhs;
//            shifted_rhs <<= i * 64;
//
//            let mut shifted_remainder = remainder;
//            shifted_remainder <<= i * 64;
//
//            for _ in 0..64 {
//                if shifted_remainder >= shifted_rhs {
//                    shifted_remainder -= shifted_rhs;
//                    chunk_quotient = (chunk_quotient << 1) | 1;
//                } else {
//                    chunk_quotient <<= 1;
//                }
//                shifted_rhs >>= 1;
//            }
//
//        }
//        (remainder, quotient)
//    }
//}

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
            x.add(&y),
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
        assert_eq!(x.add(&y), BigInt::MAX);

        let x = BigInt::from([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(x.add(&y), BigInt::ZERO);
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
            x.expanding_mul(&y),
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
        let y = BigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        let x = BigInt::from([0, 1, 0, 0]);
        assert_eq!(y.div(&y), (BigInt::from([1, 0, 0, 0]), BigInt::ZERO));
        assert_eq!(
            y.div(&x),
            (
                BigInt::from([
                    0xfedcba9876543210,
                    0x0123456789abcdef,
                    0xfedcba9876543210,
                    0,
                ]),
                BigInt::from([0x0123456789abcdef, 0, 0, 0,])
            )
        );
        let a = BigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let b = BigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0,
        ]);
        let quotient = BigInt::from([0x124924924924920, 0, 0, 0]);
        let remainder = BigInt::from([
            0x7e3649cb031697d0,
            0x81cb031697cfe364,
            0x7e34fce968301c9b,
            0,
        ]);
        assert_eq!(a.div(&b), (quotient, remainder));
        // TODO: make test more exaustive
    }

    #[test]
    fn shift_left() {
        let x = BigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        let shifted = BigInt::from([
            0x3456789abcdef000,
            0xcba9876543210012,
            0x3456789abcdeffed,
            0xcba9876543210012,
            0xfed,
        ]);
        assert_eq!(x.shift_left(12), shifted);
    }

    #[test]
    fn left_align() {
        let mut x = BigInt::from([0xfedcba9876543210, 0x0123456789abcdef, 0xfedcba9876543210, 0x0823456789abcdef]);
        let shift_amount = x.left_align();
        let aligned = BigInt::from([0xedcba98765432100, 0x123456789abcdeff, 0xedcba98765432100, 0x823456789abcdeff]);
        assert_eq!(x, aligned);
        assert_eq!(shift_amount, 4);
    }
}
