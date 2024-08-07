//! This module provides large unsigned integers.
//!
//! For signed integers, use [`BigInt`](`super::BigInt`).
use super::{BigInt, FromNegErr};
use core::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
/// An unsigned integer of size `N * 64` bits.
///
/// Internally, [`UBigInt<N>`] is a little-endian `[u64; N]`
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct UBigInt<const N: usize>(pub [u64; N]);

impl<const N: usize> UBigInt<N> {
    /// Constructs a new `UBigInt` of length `N` from a little-endian `[u64; N]`
    pub const fn new(value: [u64; N]) -> Self {
        Self(value)
    }

    /// The zero value of [`UBigInt<N>`]
    ///
    /// Note: this has the same value as [`UBigInt<N>::MIN`].
    pub const ZERO: Self = Self::new([u64::MIN; N]);

    /// The maximum value representable by [`UBigInt<N>`].
    pub const MAX: Self = Self::new([u64::MAX; N]);

    /// The minimum value representable by [`UBigInt<N>`].
    ///
    /// This has the same value as [`UBigInt<N>::ZERO`].
    pub const MIN: Self = Self::ZERO;

    /// A `UBigInt` with value 1
    pub const ONE: Self = {
        let mut one = Self::ZERO;
        one.0[0] = 1;
        one
    };

    /// Subtracts `rhs` from `self`, returning the result and whether the operation
    /// overflowed.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness:
    /// This operation is constant-time.
    pub fn overflowing_sub(&self, rhs: &Self) -> (Self, bool) {
        let mut buf = *self;
        let overflowed = buf.overflowing_sub_assign(rhs);
        (buf, overflowed)
    }

    /// Subtracts `rhs` from `self`, storing the result in `self` and
    /// returning whether the operation overflowed.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness:
    /// This operation is constant-time.
    pub fn overflowing_sub_assign(&mut self, rhs: &Self) -> bool {
        let mut carry = false;
        for i in 0..N {
            // TODO: use libcore implementation once stabilized
            (self.0[i], carry) = super::carry_sub(self.0[i], rhs.0[i], carry);
        }
        carry
    }

    /// Adds `self` and `rhs`, returning the result and whether the operation
    /// overflowed.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness:
    /// This operation is constant-time.
    pub fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        let mut buf = *self;
        let overflowed = buf.overflowing_add_assign(rhs);
        (buf, overflowed)
    }

    /// Adds `self` and `rhs`, storing the result in `self` and
    /// returning whether the operation overflowed.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness:
    /// This operation is constant-time.
    pub fn overflowing_add_assign(&mut self, rhs: &Self) -> bool {
        let mut carry = false;
        for i in 0..N {
            // TODO: use core implementation once stabilized
            (self.0[i], carry) = super::carry_add(self.0[i], rhs.0[i], carry);
        }
        carry
    }

    /// Returns the number of used digits in `self`.
    ///
    /// This is *not* the same as [`Self::len()`].
    ///
    /// # Constant-timedness:
    /// This operation is *NOT* constant-time.
    /// If constant-time is needed, use [`Self::count_digits()`].
    ///
    /// Note: this function has not yet been benchmarked. It may not actually be any faster.
    pub fn count_digits_fast(&self) -> usize {
        for (count, digit) in self.0.iter().rev().enumerate() {
            if *digit != 0 {
                return N - count;
            };
        }
        0
    }

    /// Returns the number of digits in `self`.
    ///
    /// This is *not* the same as [`Self::len()`].
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    /// If constant-time is not needed, consider using [`Self::count_digits_fast()`].
    ///
    /// Note: this function has not yet been benchmarked. It may not actually be any slower.
    pub fn count_digits(&self) -> usize {
        let mut num_digts = 0;
        let mut digit_encounterd = false;
        for digit in self.0.iter().rev() {
            digit_encounterd |= *digit != 0;
            num_digts += digit_encounterd as usize;
        }
        num_digts
    }

    /// Adds `self` and `rhs` and returns the result.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness:
    /// This operation is constant-time.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.add_assign(rhs);
        buf
    }

    /// Adds `self` and `rhs` and stores the result in `self`
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Constant-timedness:
    /// This operation is constant-time.
    pub fn add_assign(&mut self, rhs: &Self) {
        let mut carry = false;
        for i in 0..N {
            // TODO: use core implementation once stabilized
            (self.0[i], carry) = super::carry_add(self.0[i], rhs.0[i], carry);
        }
    }

    /// Subtracts `rhs` from `self` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.sub_assign(rhs);
        buf
    }

    /// Subtracts `rhs` from `self` and stores the result in `self`
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation
    pub fn sub_assign(&mut self, rhs: &Self) {
        let mut carry = false;
        for i in 0..N {
            // TODO: use libcore implementation once stabilized
            (self.0[i], carry) = super::carry_sub(self.0[i], rhs.0[i], carry);
        }
    }

    /// Returns `self` if `rhs` is `true`, otherwise `Self::ZERO`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn and_bool(&self, rhs: bool) -> Self {
        let mut buf = *self;
        buf.and_bool_assign(rhs);
        buf
    }

    /// reasigns `self` to equal `self` if `rhs` is `true`, otherwise `Self::ZERO`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn and_bool_assign(&mut self, rhs: bool) {
        let mask = (rhs as u64).wrapping_neg();
        for digit in self.0.iter_mut() {
            *digit &= mask
        }
    }

    /// Shifts `self` to the left until the most significant bit is on.
    ///
    /// This function does not align leading 0-digits; it only considers the ones after the last
    /// leading `0`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn left_align(&mut self) -> u64 {
        let num_digits = self.count_digits();
        assert_ne!(num_digits, 0);
        let left_shift = self.0[num_digits - 1].leading_zeros() as u64;
        self.shift_left_assign(left_shift);
        left_shift
    }

    /// Performs a bitshift `rhs % 64` to the right and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn shift_right_assign(&mut self, mut rhs: u64) {
        rhs %= 64;
        let left_shift = (64 - rhs) % 64;
        let mask = ((rhs != 0) as u64).wrapping_neg();

        for i in 0..N - 1 {
            self.0[i] >>= rhs;
            self.0[i] |= (self.0[i + 1] << left_shift) & mask;
        }
        self.0[N - 1] >>= rhs;
    }

    /// Performs a bitshift `rhs % 64` to the right and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn shift_right(&self, rhs: u64) -> Self {
        let mut buf = *self;
        buf.shift_right_assign(rhs);
        buf
    }

    /// Performs a bitshift `rhs % 64` to the left and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn shift_left_assign(&mut self, mut rhs: u64) {
        rhs %= 64;
        let right_shift = (64 - rhs) % 64;
        let mask = ((rhs != 0) as u64).wrapping_neg();

        for i in (1..N).rev() {
            self.0[i] <<= rhs;
            self.0[i] |= (self.0[i - 1] >> right_shift) & mask;
        }
        self.0[0] <<= rhs;
    }

    /// Performs a bitshift `rhs` to the right and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn shift_left(&self, rhs: u64) -> Self {
        let mut buf = *self;
        buf.shift_left_assign(rhs);
        buf
    }

    /// Converts `self` into its one's compliment.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn not_assign(&mut self) {
        for digit in self.0.iter_mut() {
            *digit = !*digit
        }
    }

    /// Returns the one's compliment of `self`
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn not(&self) -> Self {
        let mut buf = *self;
        buf.not_assign();
        buf
    }

    /// Performs a bitwise `XOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn xor_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit ^= rhs_digit;
        }
    }

    /// Performs a bitwise `XOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn xor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.xor_assign(rhs);
        buf
    }

    /// Performs a bitwise `AND` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn and_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit &= rhs_digit;
        }
    }

    /// Performs a bitwise `AND` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn and(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.and_assign(rhs);
        buf
    }

    /// Performs a bitwise `OR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn or_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit |= rhs_digit;
        }
    }

    /// Performs a bitwise `OR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn or(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.or_assign(rhs);
        buf
    }

    /// Performs a bitwise `NOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn nor_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit = !(*digit | rhs_digit);
        }
    }

    /// Performs a bitwise `NOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn nor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.nor_assign(rhs);
        buf
    }

    /// Performs a bitwise `XNOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn xnor_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit = !(*digit ^ rhs_digit);
        }
    }

    /// Performs a bitwise `XNOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn xnor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.xnor_assign(rhs);
        buf
    }

    /// Performs a bitwise `NAND` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn nand_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit = !(*digit & rhs_digit);
        }
    }

    /// Performs a bitwise `NAND` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness:
    /// This is a constant-time operation.
    pub fn nand(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.nand_assign(rhs);
        buf
    }

    /// Returns the total number of digits in `self`.
    ///
    /// The returned value is `N`.
    ///
    /// Note: this is not the same as [`Self::count_digits()`].
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        N
    }
}

// TODO: figure out what this does to see if it can be simplified
fn partial_div(m0: u64, m1: u64, d1: u64, d0: u64) -> u64 {
    let mut r = ((m0 as u128) << 64) | m1 as u128;
    let mut d = ((d0 as u128) << 64) | d1 as u128;
    let mut q: u64 = 0;

    for _ in 0..64 {
        q <<= 1;
        if r >= d {
            q |= 1;
            r -= d;
        }
        d >>= 1;
    }

    let mask = (q >> (64 - 1)).wrapping_neg();

    q <<= 1;
    q |= (r >= d) as u64;

    q | mask
}

macro_rules! impl_non_generic {
    ($n:literal) => {
        impl UBigInt<$n> {
            const _POSITIVE_N: () = assert!($n > 0);
            /// Multiplies `self` and `rhs`.
            ///
            /// The output is twice as large, so overflow never occurs.
            ///
            /// # Constant-timedness:
            /// This is a constant-time operation.
            pub fn widening_mul(&self, rhs: &Self) -> UBigInt<{ $n * 2 }> {
                let mut product = [0u64; $n * 2];
                for i in 0..self.len() {
                    let mut carry = 0;
                    for j in 0..rhs.len() {
                        // TODO: use libcore carry_mul once stabilized
                        let result = super::carry_mul(self.0[i], rhs.0[j], carry);
                        let (sum, overflowed) = product[i + j].overflowing_add(result.0);
                        product[i + j] = sum;
                        // TODO: can this overflow?
                        product[i + j + 1] += overflowed as u64;
                        carry = result.1;
                        //let temp = product[i + j];
                        //(product[i + j], carry) = super::carry_mul(self.0[i], rhs.0[j], carry);
                        //product[i + j]
                    }
                    product[i + rhs.len()] = carry;
                }
                product.into()
            }

            /// Left-shifts `self` `rhs % 64` bits.
            ///
            /// The output is 64 bits longer, so ovelflow never occurs.
            ///
            /// # Constant-timedness:
            /// This is a constant-time operation.
            pub fn widening_shift_left(&self, mut rhs: u64) -> UBigInt<{ $n + 1 }> {
                rhs %= 64;
                let mut expanded = [0u64; $n + 1];
                let right_shift = (64 - rhs) % 64;
                let mask = ((rhs != 0) as u64).wrapping_neg();

                expanded[$n] = self.0[$n - 1] >> right_shift & mask;
                for i in (1..$n).rev() {
                    expanded[i] = self.0[i] << rhs;
                    expanded[i] |= (self.0[i - 1] >> right_shift) & mask;
                }
                expanded[0] = self.0[0] << rhs;
                expanded.into()
            }

            /// Divides `self` by `rhs`, returning the quotient and the remainder.
            ///
            /// # Panics
            /// This function will panic if `divisor == Self::ZERO`.
            ///
            /// # Constant-timedness:
            /// TODO: document constant-timedness
            pub fn div(&self, rhs: &Self) -> (Self, Self) {
                assert_ne!(*rhs, Self::ZERO);

                let num_len = self.count_digits() + 1;
                let div_len = rhs.count_digits();

                // Normalize both numerator and denominator
                let norm_shift;
                let sdiv = {
                    let mut sdiv = *rhs;
                    norm_shift = sdiv.left_align();
                    sdiv
                };
                let mut snum = self.widening_shift_left(norm_shift);

                // `div_n` is guaranteed to be at least 1
                let d0 = sdiv.0[div_len - 1];
                let d1 = match div_len {
                    0 => unreachable!(),
                    1 => 0,
                    _ => sdiv.0[div_len - 2],
                };

                let num_loops = num_len.saturating_sub(div_len);

                let mut quotient = Self::ZERO;
                let mut quotient_pos = num_loops;

                for (win_bot, win_top) in (0..num_loops).zip(num_len - num_loops..num_len).rev() {
                    let mut temp = UBigInt::<{ $n + 1 }>::ZERO;
                    let mut partial_quotient =
                        partial_div(snum.0[win_top], snum.0[win_top - 1], d1, d0);

                    // multiply `sdiv` by `q`
                    let mut mul_carry = 0;
                    for i in 0..div_len {
                        (temp.0[i], mul_carry) =
                            super::carry_mul(sdiv.0[i], partial_quotient, mul_carry);
                    }
                    temp.0[div_len] = mul_carry;

                    // subtract result from `snum`
                    let mut sub_carry = false;
                    for i in 0..div_len + 1 {
                        (snum.0[win_bot + i], sub_carry) =
                            super::carry_sub(snum.0[win_bot + i], temp.0[i], sub_carry);
                    }

                    partial_quotient -= sub_carry as u64;

                    // add back if overflow occured
                    let mask = (sub_carry as u64).wrapping_neg();
                    let mut add_carry = false;
                    for i in 0..div_len {
                        (snum.0[win_bot + i], add_carry) =
                            super::carry_add(snum.0[win_bot + i], sdiv.0[i] & mask, add_carry);
                    }
                    snum.0[win_top] = snum.0[win_top].wrapping_add(add_carry as u64);
                    debug_assert!(snum.0[win_top] == 0);

                    quotient_pos -= 1;
                    quotient.0[quotient_pos] = partial_quotient;
                }
                // Un-normalize remainder
                snum.shift_right_assign(norm_shift);
                // we can safely unwrap because because `snum.len()` is 5
                (quotient, snum.0[..$n].try_into().unwrap())
            }

            /// Divides `self` by `rhs` and stores the result in `self`
            pub fn div_assign(&mut self, rhs: &Self) {
                *self = self.div(rhs).0;
            }

            /// converts a big-endian byte array to a [`UBigInt`]
            // TODO: implement this for all values of `N` once const_generic operations are stabilized
            pub fn from_be_bytes(bytes: [u8; $n * 8]) -> Self {
                // TODO: consider using uninitialized array
                let mut output = [0u64; $n];
                // TODO: use array_chunks once stabilized
                for (chunk, digit) in bytes.rchunks_exact(8).zip(output.iter_mut()) {
                    *digit = u64::from_be_bytes(chunk.try_into().unwrap())
                }
                output.into()
            }
        }
    };
}

impl_non_generic!(4);
impl_non_generic!(8);

impl<const N: usize> Ord for UBigInt<N> {
    // TODO: make this constant-time?
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..N).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl<const N: usize> PartialOrd for UBigInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> From<[u64; N]> for UBigInt<N> {
    fn from(value: [u64; N]) -> Self {
        Self::new(value)
    }
}

impl<const N: usize> From<UBigInt<N>> for [u64; N] {
    fn from(value: UBigInt<N>) -> Self {
        value.0
    }
}

impl<const N: usize> From<u64> for UBigInt<N> {
    fn from(value: u64) -> Self {
        let mut big_int = [0u64; N];
        big_int[0] = value;
        big_int.into()
    }
}

impl<const N: usize> Default for UBigInt<N> {
    fn default() -> Self {
        Self::ZERO
    }
}

// TODO: uncomment this line once `where` clauses are supported for const-generics
//impl<const N: usize, const O: usize> From<UBigInt<O>> for UBigInt<N> {
//    fn from(value: UBigInt<O>) -> Self {
//        let mut output = Self::ZERO;
//        let min = core::cmp::min(N, O);
//        output.0[..min].copy_from_slice(&value.0[..min]);
//        output
//    }
//}

impl From<UBigInt<9>> for UBigInt<4> {
    fn from(value: UBigInt<9>) -> Self {
        Self(value.0[..4].try_into().unwrap())
    }
}

impl From<UBigInt<8>> for UBigInt<4> {
    fn from(value: UBigInt<8>) -> Self {
        Self(value.0[..4].try_into().unwrap())
    }
}

impl From<UBigInt<4>> for UBigInt<8> {
    fn from(value: UBigInt<4>) -> Self {
        let mut output = Self::ZERO;
        output.0[..4].copy_from_slice(&value.0);
        output
    }
}

impl<const N: usize> TryFrom<&[u64]> for UBigInt<N> {
    type Error = core::array::TryFromSliceError;
    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        Ok(Self(<[u64; N]>::try_from(value)?))
    }
}

impl<const N: usize> TryFrom<BigInt<N>> for UBigInt<N> {
    type Error = FromNegErr;
    fn try_from(value: BigInt<N>) -> Result<Self, Self::Error> {
        if value.is_negative() {
            return Err(FromNegErr);
        };
        Ok(value.digits)
    }
}

#[cfg(test)]
mod tests {

    use super::UBigInt;

    #[test]
    fn add() {
        let x = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let y = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x.add(&y), UBigInt::MAX);

        let x = UBigInt::from([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(x.add(&y), UBigInt::ZERO);
    }

    #[test]
    fn sub() {
        let x = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let y = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(UBigInt::MAX.sub(&x), y);

        let x = UBigInt::from([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(UBigInt::ZERO.sub(&y), x);
    }

    #[test]
    fn widening_mul() {
        let x = UBigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x1000000000000000,
        ]);
        let y = UBigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000010000,
            0x0000000000000000,
        ]);
        let product = UBigInt::from([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000001000,
            0x0000000000000000,
        ]);
        assert_eq!(x.widening_mul(&y), product);

        let y = UBigInt::from([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(y.widening_mul(&UBigInt::ONE), y.into());
        let a = UBigInt::from([0x124924924924924, 0, 0, 0]);
        let b = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0,
        ]);
        // TODO: make this hex
        let product = UBigInt::from([
            0x80a670cd733d9a40,
            0x7f584250f1dbea8b,
            0x80a7bdaf0e241574,
            81985529216486895,
        ]);
        assert_eq!(UBigInt::<4>::from(a.widening_mul(&b)), product);
    }

    #[test]
    fn div() {
        let y = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(y.div(&y), (UBigInt::ONE, UBigInt::ZERO));

        let x = UBigInt::from([0, 1, 0, 0]);
        let quotient = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0,
        ]);
        let remainder = UBigInt::from([0x0123456789abcdef, 0, 0, 0]);
        assert_eq!(y.div(&x), (quotient, remainder));

        assert_eq!(quotient.div(&y), (UBigInt::ZERO, quotient));

        let a = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let b = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0,
        ]);
        let quotient = UBigInt::from([0x124924924924924, 0, 0, 0]);
        let remainder = UBigInt::from([
            0x7e3649cb031697d0,
            0x81cb031697cfe364,
            0x7e34fce968301c9b,
            0,
        ]);
        assert_eq!(a.div(&b), (quotient, remainder));
    }

    #[test]
    fn widening_shift_left() {
        let x = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        let shifted = UBigInt::from([
            0x3456789abcdef000,
            0xcba9876543210012,
            0x3456789abcdeffed,
            0xcba9876543210012,
            0xfed,
        ]);
        assert_eq!(x.widening_shift_left(12), shifted);

        let mut widened_x = UBigInt::ZERO;
        widened_x.0[..x.len()].copy_from_slice(&x.0[..]);
        assert_eq!(x.widening_shift_left(0), widened_x);
    }

    #[test]
    fn left_align() {
        let mut x = UBigInt::from([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0823456789abcdef,
        ]);
        let shift_amount = x.left_align();
        let aligned = UBigInt::from([
            0xedcba98765432100,
            0x123456789abcdeff,
            0xedcba98765432100,
            0x823456789abcdeff,
        ]);
        assert_eq!(x, aligned);
        assert_eq!(shift_amount, 4);
    }

    #[test]
    fn count_digits_fast() {
        let x = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x.count_digits_fast(), 4);

        let y = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0,
            0xfedcba9876543210,
        ]);
        assert_eq!(y.count_digits_fast(), 4);

        let z = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0,
        ]);
        assert_eq!(z.count_digits_fast(), 3);
    }

    #[test]
    fn count_digits() {
        let x = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x.count_digits(), 4);

        let y = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0,
            0xfedcba9876543210,
        ]);
        assert_eq!(y.count_digits(), 4);

        let z = UBigInt::from([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0,
        ]);
        assert_eq!(z.count_digits(), 3);
    }
}
