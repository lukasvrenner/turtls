const G: Point = Point::new(
    FieldEl::new([
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ]),
    FieldEl::new([
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ]),
);

const N: FieldEl = FieldEl::new([
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
]);

struct Point(FieldEl, FieldEl);

impl Point {
    const fn new(x: FieldEl, y: FieldEl) -> Point {
        Point(x, y)
    }

    fn mult_scalar(&self, scalar: FieldEl) -> Point {
        todo!();
    }
}

/// Represents a big integer less than `N`
// While individual inner-integers are native-endian, as a whole `FieldElement` is big-endian
// We use big-endian because that allows us to simply `#[derive()]` our comparison traits
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct FieldEl([u8; 32]);

impl FieldEl {
    const fn new(value: [u8; 32]) -> FieldEl {
        FieldEl(value)
    }

    /// Adds `rhs` to `self`
    ///
    /// # Safetey
    ///
    /// One of `FieldElement`'s invariants is that the value is less than `N`.
    /// This method does not guarantee this, so it is up to the user to do so.
    /// for a modular addition, use `FieldElement` implements `std::ops::Add`
    ///
    ///  TODO: define overflow behavior
    unsafe fn add_unmodulated(self, rhs: FieldEl) -> FieldEl {
        let mut sum = [0u8; 32];
        let mut carry = false;
        for i in (0..32).rev() {
            // TODO: use carrying_add() once stabilized
            let (sum1, overflowed1) = self[i].overflowing_add(rhs.0[i]);
            let (sum2, overflowed2) = sum1.overflowing_add(carry as u8);
            sum[i] = sum2;
            carry = overflowed1 || overflowed2;
        }
        sum.into()
    }

    fn mul_unmodulated(self, rhs: FieldEl) -> PartialFieldEl {
        let mut product = [0u8; 64];
        for i in (0..32).rev() {
            let mut carry = 0;
            for j in (0..32).rev() {
                // TODO: use carrying_mul() once stabilized
                let remainder = self[j]
                    .wrapping_mul(rhs[i])
                    .wrapping_add(carry)
                    .wrapping_add(product[i + j]);
                product[i + j] = remainder;
                carry = ((self[j] as u16 * rhs[i] as u16 + carry as u16 + product[i + j] as u16)
                    / 256) as u8;
            }
            product[i + 32] = carry;
        }
        product.into()
    }
}

impl From<[u8; 32]> for FieldEl {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

impl From<FieldEl> for [u8; 32] {
    fn from(value: FieldEl) -> Self {
        value.0
    }
}

impl std::ops::Deref for FieldEl {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Mul for FieldEl {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl std::ops::Add for FieldEl {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        // SAFETY: We guarntee that the return is less than `N` by subtracting `N` until it is
        unsafe {
            let mut sum = self.add_unmodulated(rhs);
            while sum > N {
                sum = sum - N;
            }
            sum
        }
    }
}

impl std::ops::Sub for FieldEl {
    type Output = Self;
    /// # Panics
    ///
    /// In debug mode, we panic if `self` < `rhs`
    ///
    /// TODO: define overflow behavior
    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert!(self >= rhs);
        let mut difference = [0u8; 32];
        let mut carry = false;
        for i in (0..32).rev() {
            // TODO: use carrying_sub() once stabilized
            let (sum1, overflowed1) = self[i].overflowing_sub(rhs.0[i]);
            let (sum2, overflowed2) = sum1.overflowing_sub(carry as u8);
            difference[i] = sum2;
            carry = overflowed1 || overflowed2;
        }
        difference.into()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct PartialFieldEl([u8; 64]);

impl PartialFieldEl {
    const fn new(value: [u8; 64]) -> PartialFieldEl {
        PartialFieldEl(value)
    }
}

impl From<PartialFieldEl> for [u8; 64] {
    fn from(value: PartialFieldEl) -> Self {
        value.0
    }
}

impl From<[u8; 64]> for PartialFieldEl {
    fn from(value: [u8; 64]) -> Self {
        Self::new(value)
    }
}

impl std::ops::Deref for PartialFieldEl {
    type Target = [u8; 64];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn generate_signature(
    msg: &[u8],
    key: [u8; 32],
    hash_func: fn(&[u8]) -> [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let hash = FieldEl::from(hash_func(msg));
    let key = FieldEl::from(key);

    let mut r = FieldEl::from([0u8; 32]);
    let mut s = FieldEl::from([0u8; 32]);

    // this will eventually exit because `key`
    // is generated non-deterministically
    while r == FieldEl::from([0u8; 32]) || s == FieldEl::from([0u8; 32]) {
        let scalar = generate_secret_number();
        let inverse = inverse(scalar);

        let new_point = G.mult_scalar(scalar);
        r = new_point.0;
        s = inverse * (hash + r * key);
    }
    (r.into(), s.into())
}

fn generate_secret_number() -> FieldEl {
    todo!()
}

fn inverse(num: FieldEl) -> FieldEl {
    todo!();
}
