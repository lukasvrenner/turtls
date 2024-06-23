use std::ops::{Add, Deref, DerefMut, Mul, Sub};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BigInt<const N: usize>([u64; N]);

impl<const N: usize> BigInt<N> {
    const fn new(value: [u64; N]) -> Self {
        BigInt(value)
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
        let mut sum = [064; N];
        let mut carry = false;
        for i in (0..N).rev() {
            // TODO: use libstd implementation once stabilized
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
            // TODO: use libstd implementation once stabilized
            (diff[i], carry) = carry_sub(self[i], rhs[i], carry);
        }
        diff.into()
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
