//! Unsigned large integers.
//!
//! Unlike many multi-precision libraries, these integers have a fixed (but arbitrary) size.
//!
//! Due to current limitations in Rust, some functions can only be applied on a per-size basis,
//! rather than being generic over any size. This will hopefully be fixed some day.

use super::{carry_mul, BigInt, FromNegErr};
use core::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};

/// An unsigned integer of size `N * 64` bits.
///
/// Internally, [`UBigInt<N>`] is a little-endian `[u64; N]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct UBigInt<const N: usize>(pub [u64; N]);

impl<const N: usize> core::fmt::Display for UBigInt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self, f)
    }
}

impl<const N: usize> core::fmt::LowerHex for UBigInt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("0x")?;
        for i in self.0.iter().rev() {
            write!(f, "{:016x}", i)?
        }
        Ok(())
    }
}

impl<const N: usize> core::fmt::UpperHex for UBigInt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("0x")?;
        for i in self.0.iter().rev() {
            write!(f, "{:016X}", i)?
        }
        Ok(())
    }
}

impl<const N: usize> core::fmt::Debug for UBigInt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("{ ")?;
        for i in self.0 {
            write!(f, "{:016x}, ", i)?
        }
        f.write_str("}")?;
        Ok(())
    }
}

impl<const N: usize> UBigInt<N> {
    /// Constructs a new `UBigInt` of length `N` from a little-endian `[u64; N]`.
    ///
    /// This is the same as `Self(value)`
    pub const fn new(value: [u64; N]) -> Self {
        Self(value)
    }

    pub const fn from_ref(value: &[u64; N]) -> &Self {
        let ptr = value as *const [u64; N] as *const UBigInt<N>;
        // SAFETY: `UBigInt<N>` is repr(transparent) and therefore has the same memory layout as
        // `[u64; N]`.
        unsafe { &*ptr }
    }

    pub const fn from_ref_mut(value: &mut [u64; N]) -> &mut Self {
        let ptr = value as *mut [u64; N] as *mut UBigInt<N>;
        // SAFETY: `UBigInt<N>` is repr(transparent) and therefore has the same memory layout as
        // `[u64; N]`.
        unsafe { &mut *ptr }
    }

    /// The zero value of [`UBigInt<N>`]
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    ///
    /// assert_eq!(UBigInt::<4>::ZERO, UBigInt::MIN);
    /// assert_eq!(UBigInt::<4>::ZERO.count_digits(), 0);
    /// ```
    ///
    /// This has the same value as [`UBigInt<N>::MIN`].
    pub const ZERO: Self = Self([u64::MIN; N]);

    /// The maximum value representable by [`UBigInt<N>`].
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    ///
    /// assert_eq!(UBigInt::<4>::MAX.count_digits(), 4);
    /// ```
    pub const MAX: Self = Self([u64::MAX; N]);

    /// The minimum value representable by [`UBigInt<N>`].
    ///
    /// This has the same value as [`UBigInt<N>::ZERO`].
    pub const MIN: Self = Self::ZERO;

    /// A [`UBigInt`] with value `1`.
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
    /// # Constant-timedness
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
    /// # Constant-timedness
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
    /// # Constant-timedness
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
    /// # Constant-timedness
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
    /// Note: this function has not yet been benchmarked. It may not actually be any faster.
    ///
    /// # Constant-timedness
    /// This operation is *NOT* constant-time.
    /// If constant-time is needed, use [`Self::count_digits()`].
    pub fn count_digits_fast(&self) -> usize {
        for (count, digit) in self.0.into_iter().rev().enumerate() {
            if digit != 0 {
                return N - count;
            };
        }
        0
    }

    /// Returns the number of digits in `self`.
    ///
    /// This is the same as `floor(log64(self))`
    ///
    /// This is *not* the same as [`Self::len()`].
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    ///
    /// let large_int = UBigInt([0x0123456789abcdef, 0xfedcba9876543210, 0x0, 0x0]);
    ///
    /// assert_eq!(large_int.count_digits(), 2);
    /// ```
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    /// If constant-time is not needed, consider using [`Self::count_digits_fast()`].
    pub fn count_digits(&self) -> usize {
        let mut num_digts = 0;
        let mut digit_encounterd = false;
        for digit in self.0.iter().rev() {
            digit_encounterd |= *digit != 0;
            num_digts += digit_encounterd as usize;
        }
        num_digts
    }

    /// Returns `self + rhs`, wrapping on overflow.
    ///
    /// If overflow occurs, it wraps around.
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    ///
    /// assert_eq!(UBigInt::<4>::ZERO.add(&UBigInt::ONE), UBigInt::ONE);
    /// assert_eq!(UBigInt::<4>::MAX.add(&UBigInt::ONE), UBigInt::ZERO);
    /// ```
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.add_assign(rhs);
        buf
    }

    /// Sets `self` to `self + rhs`, wrapping on overflow.
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    /// let mut zero: UBigInt<4> = UBigInt::ZERO;
    /// let mut max: UBigInt<4> = UBigInt::MAX;
    ///
    /// zero.add_assign(&UBigInt::ONE);
    /// max.add_assign(&UBigInt::ONE);
    ///
    /// assert_eq!(zero, UBigInt::ONE);
    /// assert_eq!(max, UBigInt::ZERO);
    /// ```
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn add_assign(&mut self, rhs: &Self) {
        let mut carry = false;
        for i in 0..N {
            // TODO: use core implementation once stabilized
            (self.0[i], carry) = super::carry_add(self.0[i], rhs.0[i], carry);
        }
    }

    pub fn double(&self) -> Self {
        self.add(self)
    }

    pub fn double_assign(&mut self) {
        let mut carry = false;
        for i in 0..N {
            // TODO: use core implementation once stabilized
            (self.0[i], carry) = super::carry_add(self.0[i], self.0[i], carry);
        }
    }

    /// Sets `self` to `self * digit`, wrapping on overflow.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn mul_digit_assign(&mut self, digit: u64) {
        let mut carry = 0;
        for i in self.0.iter_mut() {
            (*i, carry) = carry_mul(*i, digit, carry);
        }
    }

    /// Returns `self * digit`, wrapping on overflow.
    pub fn mul_digit(&self, digit: u64) -> Self {
        let mut buf = *self;
        buf.mul_digit_assign(digit);
        buf
    }

    pub fn overflowing_mul_digit(&self, digit: u64) -> (Self, u64) {
        let mut buf = *self;
        let overflow = buf.overflowing_mul_digit_assign(digit);
        (buf, overflow)
    }

    pub fn overflowing_mul_digit_assign(&mut self, digit: u64) -> u64 {
        let mut carry = 0;
        for i in self.0.iter_mut() {
            (*i, carry) = carry_mul(*i, digit, carry);
        }
        carry
    }

    /// Returns `self - rhs`, wrapping on overflow.
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    ///
    /// assert_eq!(UBigInt::<4>::ONE.sub(&UBigInt::ONE), UBigInt::ZERO);
    /// assert_eq!(UBigInt::<4>::ZERO.sub(&UBigInt::ONE), UBigInt::MAX);
    /// ```
    ///
    /// # Constant-timedness
    /// This is a constant-time operation
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.sub_assign(rhs);
        buf
    }

    /// Sets `self` to `self - rhs`, wrapping on overflow.
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    /// let mut one: UBigInt<4> = UBigInt::ONE;
    /// let mut zero: UBigInt<4> = UBigInt::ZERO;
    ///
    /// one.sub_assign(&UBigInt::ONE);
    /// zero.sub_assign(&UBigInt::ONE);
    ///
    /// assert_eq!(one, UBigInt::ZERO);
    /// assert_eq!(zero, UBigInt::MAX);
    /// ```
    ///
    /// # Constant-timedness
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
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn and_bool(&self, rhs: bool) -> Self {
        let mut buf = *self;
        buf.and_bool_assign(rhs);
        buf
    }

    /// reasigns `self` to equal `self` if `rhs` is `true`, otherwise `Self::ZERO`.
    ///
    /// # Constant-timedness
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
    /// # Constant-timedness
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
    /// # Constant-timedness
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
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn shift_right(&self, rhs: u64) -> Self {
        let mut buf = *self;
        buf.shift_right_assign(rhs);
        buf
    }

    /// Performs a bitshift `rhs % 64` to the left and stores the result in `self`.
    ///
    /// # Constant-timedness
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
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn shift_left(&self, rhs: u64) -> Self {
        let mut buf = *self;
        buf.shift_left_assign(rhs);
        buf
    }

    /// Converts `self` into its one's compliment.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn not_assign(&mut self) {
        for digit in self.0.iter_mut() {
            *digit = !*digit
        }
    }

    /// Returns the one's compliment of `self`
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn not(&self) -> Self {
        let mut buf = *self;
        buf.not_assign();
        buf
    }

    /// Performs a bitwise `XOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn xor_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit ^= rhs_digit;
        }
    }

    /// Performs a bitwise `XOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn xor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.xor_assign(rhs);
        buf
    }

    /// Performs a bitwise `AND` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn and_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit &= rhs_digit;
        }
    }

    /// Performs a bitwise `AND` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn and(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.and_assign(rhs);
        buf
    }

    /// Performs a bitwise `OR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn or_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit |= rhs_digit;
        }
    }

    /// Performs a bitwise `OR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn or(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.or_assign(rhs);
        buf
    }

    /// Performs a bitwise `NOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn nor_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit = !(*digit | rhs_digit);
        }
    }

    /// Performs a bitwise `NOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn nor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.nor_assign(rhs);
        buf
    }

    /// Performs a bitwise `XNOR` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn xnor_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit = !(*digit ^ rhs_digit);
        }
    }

    /// Performs a bitwise `XNOR` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn xnor(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.xnor_assign(rhs);
        buf
    }

    /// Performs a bitwise `NAND` on `self` and `rhs` and stores the result in `self`.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn nand_assign(&mut self, rhs: &Self) {
        for (digit, rhs_digit) in self.0.iter_mut().zip(rhs.0) {
            *digit = !(*digit & rhs_digit);
        }
    }

    /// Performs a bitwise `NAND` on `self` and `rhs` and returns the result.
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    pub fn nand(&self, rhs: &Self) -> Self {
        let mut buf = *self;
        buf.nand_assign(rhs);
        buf
    }

    /// Returns the number of digits `self` can store.
    ///
    /// # Examples
    /// ```
    /// use crylib::big_int::UBigInt;
    ///
    /// assert_eq!(UBigInt::<4>::ZERO.len(), 4);
    /// assert_eq!(UBigInt::<3>::MAX.len(), 3);
    /// ```
    ///
    /// # Constant-timedness
    /// This is a constant-time operation.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Resizes a `UBigInt<N>` to a `UBigInt<O>`, truncating most significant bits if necessary.
    pub fn resize<const O: usize>(self) -> UBigInt<O> {
        let min = core::cmp::min(O, N);
        let mut new = UBigInt([0; O]);
        new.0[..min].copy_from_slice(&self.0[..min]);
        new
    }

    pub const fn get_bit(&self, bit: usize) -> bool {
        assert!(bit < u64::BITS as usize * N);
        self.0[bit / (u64::BITS as usize)] & 1 << (bit % (u64::BITS as usize)) != 0
    }

    pub fn set_bit(&mut self, bit: usize, value: bool) {
        let digit = bit / (u64::BITS) as usize;
        assert!(digit < N);
        let bit = bit % u64::BITS as usize;

        // turn bit off
        self.0[digit] &= !(1 << bit);

        // set bit to value
        self.0[digit] |= (value as u64) << bit;
    }

    pub fn set_byte(&mut self, byte: usize, value: u8) {
        let digit = byte / size_of::<u64>();
        assert!(digit < N);
        let byte = byte % size_of::<u64>() * u8::BITS as usize;

        // turn bit off
        self.0[digit] &= !(0xff << byte);

        // set bit to value
        self.0[digit] |= (value as u64) << byte;
    }

    /// Counts the number of significant bits in `self`.
    ///
    /// This is the same as `floor(log2(self))`
    pub fn count_bits(&self) -> usize {
        let num_ditis = self.count_digits().saturating_sub(1);
        let bits = u64::BITS as usize - self.0[num_ditis].leading_zeros() as usize;
        num_ditis * u64::BITS as usize + bits
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
            /// Calculates `self * rhs`, widening the output to avoid overflow.
            ///
            /// # Constant-timedness
            /// This is a constant-time operation.
            pub fn widening_mul(&self, rhs: &Self) -> UBigInt<{ $n * 2 }> {
                let mut product = [0u64; $n * 2];
                for i in 0..self.len() {
                    let mut carry = 0;
                    for j in 0..rhs.len() {
                        // TODO: use libcore carry_mul once stabilized
                        let partial_product;
                        (partial_product, carry) = super::carry_mul(self.0[i], rhs.0[j], carry);
                        let (sum, overflowed) = product[i + j].overflowing_add(partial_product);
                        product[i + j] = sum;
                        carry += overflowed as u64;
                    }
                    product[i + rhs.len()] = carry;
                }
                product.into()
            }

            /// Left-shifts `self` by `rhs % 64` bits.
            ///
            /// The output is 64 bits longer, so ovelflow never occurs.
            ///
            /// # Constant-timedness
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

            /// Calculates `self / rhs`, returning the quotient and the remainder.
            ///
            /// # Panics
            /// This function will panic if `divisor` equals `Self::ZERO`.
            ///
            /// # Constant-timedness
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

                    // multiply `sdiv` by `partial_quotient`
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
            pub fn from_be_bytes(bytes: [u8; $n * size_of::<u64>()]) -> Self {
                // TODO: consider using uninitialized array
                let mut output = [0; $n];
                // TODO: use array_chunks once stabilized
                for (chunk, digit) in bytes.rchunks_exact(size_of::<u64>()).zip(output.iter_mut()) {
                    *digit = u64::from_be_bytes(chunk.try_into().unwrap())
                }
                output.into()
            }

            /// converts a big-endian byte array to a [`UBigInt`]
            // TODO: implement this for all values of `N` once const_generic operations are stabilized
            pub fn from_le_bytes(bytes: [u8; $n * size_of::<u64>()]) -> Self {
                // TODO: consider using uninitialized array
                let mut output = [0; $n];
                // TODO: use array_chunks once stabilized
                for (chunk, digit) in bytes.chunks_exact(size_of::<u64>()).zip(output.iter_mut()) {
                    *digit = u64::from_le_bytes(chunk.try_into().unwrap())
                }
                output.into()
            }

            pub fn to_be_bytes(self) -> [u8; $n * size_of::<u64>()] {
                let mut output = [0; $n * size_of::<u64>()];
                for (digit, chunk) in self
                    .0
                    .into_iter()
                    .zip(output.chunks_exact_mut(size_of::<u64>()).rev())
                {
                    chunk.copy_from_slice(&digit.to_be_bytes());
                }
                output
            }

            pub fn to_le_bytes(self) -> [u8; $n * size_of::<u64>()] {
                let mut output = [0; $n * size_of::<u64>()];
                for (digit, chunk) in self
                    .0
                    .into_iter()
                    .zip(output.chunks_exact_mut(size_of::<u64>()))
                {
                    chunk.copy_from_slice(&digit.to_le_bytes());
                }
                output
            }
        }
    };
}

impl_non_generic!(2);
impl_non_generic!(3);
impl_non_generic!(4);
impl_non_generic!(8);
impl_non_generic!(5);
impl_non_generic!(6);

impl<const N: usize> Ord for UBigInt<N> {
    // TODO: make this constant-time?
    fn cmp(&self, other: &Self) -> Ordering {
        let overflowed = self.overflowing_sub(other).1;

        if overflowed {
            return Ordering::Less;
        }

        if self.0 == other.0 {
            return Ordering::Equal;
        }
        Ordering::Greater
    }
}

impl<const N: usize> PartialOrd for UBigInt<N> {
    fn lt(&self, other: &Self) -> bool {
        self.overflowing_sub(other).1
    }

    fn le(&self, other: &Self) -> bool {
        !self.gt(other)
    }

    fn gt(&self, other: &Self) -> bool {
        other.overflowing_sub(self).1
    }

    fn ge(&self, other: &Self) -> bool {
        !self.lt(other)
    }

    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> From<[u64; N]> for UBigInt<N> {
    fn from(value: [u64; N]) -> Self {
        Self(value)
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

impl<const N: usize> AsRef<[u64; N]> for UBigInt<N> {
    fn as_ref(&self) -> &[u64; N] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u64; N]> for UBigInt<N> {
    fn as_mut(&mut self) -> &mut [u64; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<UBigInt<N>> for [u64; N] {
    fn as_ref(&self) -> &UBigInt<N> {
        todo!()
    }
}

impl<const N: usize> AsMut<UBigInt<N>> for [u64; N] {
    fn as_mut(&mut self) -> &mut UBigInt<N> {
        UBigInt::from_ref_mut(self)
    }
}

#[cfg(test)]
mod tests {

    use super::UBigInt;

    #[test]
    fn add() {
        let x = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let y = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x.add(&y), UBigInt::MAX);

        let x = UBigInt([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(x.add(&y), UBigInt::ZERO);
    }

    #[test]
    fn sub() {
        let x = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let y = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(UBigInt::MAX.sub(&x), y);

        let x = UBigInt([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(UBigInt::ZERO.sub(&y), x);
    }

    #[test]
    fn widening_mul() {
        let x = UBigInt([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x1000000000000000,
        ]);
        let y = UBigInt([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000010000,
            0x0000000000000000,
        ]);
        let product = UBigInt([
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

        let y = UBigInt([
            0xfedcba9876543211,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert_eq!(y.widening_mul(&UBigInt::ONE), y.resize());
        let a = UBigInt([0x124924924924924, 0, 0, 0]);
        let b = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0000000000000000,
        ]);
        // TODO: make this hex
        let product = UBigInt([
            0x80a670cd733d9a40,
            0x7f584250f1dbea8b,
            0x80a7bdaf0e241574,
            81985529216486895,
        ]);
        assert_eq!(a.widening_mul(&b).resize(), product);
    }

    #[test]
    fn div() {
        let y = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(y.div(&y), (UBigInt::ONE, UBigInt::ZERO));

        let x = UBigInt([0, 1, 0, 0]);
        let quotient = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0000000000000000,
        ]);
        let remainder = UBigInt([0x0123456789abcdef, 0, 0, 0]);
        assert_eq!(y.div(&x), (quotient, remainder));

        assert_eq!(quotient.div(&y), (UBigInt::ZERO, quotient));

        let a = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        let b = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0000000000000000,
        ]);
        let quotient = UBigInt([0x124924924924924, 0, 0, 0]);
        let remainder = UBigInt([
            0x7e3649cb031697d0,
            0x81cb031697cfe364,
            0x7e34fce968301c9b,
            0x0000000000000000,
        ]);
        assert_eq!(a.div(&b), (quotient, remainder));
    }

    #[test]
    fn widening_shift_left() {
        let x = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        let shifted = UBigInt([
            0x3456789abcdef000,
            0xcba9876543210012,
            0x3456789abcdeffed,
            0xcba9876543210012,
            0x0000000000000fed,
        ]);
        assert_eq!(x.widening_shift_left(12), shifted);

        let mut widened_x = UBigInt::ZERO;
        widened_x.0[..x.len()].copy_from_slice(&x.0[..]);
        assert_eq!(x.widening_shift_left(0), widened_x);
    }

    #[test]
    fn left_align() {
        let mut x = UBigInt([
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0823456789abcdef,
        ]);
        let shift_amount = x.left_align();
        let aligned = UBigInt([
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
        let x = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x.count_digits_fast(), 4);

        let y = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0000000000000000,
            0xfedcba9876543210,
        ]);
        assert_eq!(y.count_digits_fast(), 4);

        let z = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0x0000000000000000,
        ]);
        assert_eq!(z.count_digits_fast(), 3);
        assert_eq!(UBigInt::<4>::ZERO.count_digits_fast(), 0);
    }

    #[test]
    fn count_digits() {
        let x = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0xfedcba9876543210,
        ]);
        assert_eq!(x.count_digits(), 4);

        let y = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0000000000000000,
            0xfedcba9876543210,
        ]);
        assert_eq!(y.count_digits(), 4);

        let z = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0x0000000000000000,
        ]);
        assert_eq!(z.count_digits(), 3);
        assert_eq!(UBigInt::<4>::ZERO.count_digits(), 0);
    }

    #[test]
    fn get_bit() {
        let z = UBigInt([
            0x0000000000000000,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
        ]);
        assert!(!z.get_bit(0));
        assert!(z.get_bit(64));
        assert!(z.get_bit(248));
        assert!(!z.get_bit(255));
    }

    #[test]
    fn count_bits() {
        let z = UBigInt([
            0x0000000000000000,
            0x0123456789abcdef,
            0x0000000000000000,
            0xf123456789abcdef,
        ]);
        assert_eq!(z.count_bits(), 256);
        let x = UBigInt([
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x0123456789abcdef,
            0x0000000000000000,
        ]);
        assert_eq!(x.count_bits(), 185);

        assert_eq!(UBigInt::<4>::ZERO.count_bits(), 0);
        assert_eq!(UBigInt::<4>::ONE.count_bits(), 1);
    }

    #[test]
    fn from_le_bytes() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let num = UBigInt([
            0x0807060504030201,
            0x100f0e0d0c0b0a09,
            0x1817161514131211,
            0x201f1e1d1c1b1a19,
        ]);
        assert_eq!(UBigInt::<4>::from_le_bytes(bytes), num);
    }

    #[test]
    fn to_le_bytes() {
        let num = UBigInt([
            0x0807060504030201,
            0x100f0e0d0c0b0a09,
            0x1817161514131211,
            0x201f1e1d1c1b1a19,
        ]);
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        assert_eq!(num.to_le_bytes(), bytes);
    }
}
