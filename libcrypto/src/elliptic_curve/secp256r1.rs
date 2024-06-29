use crate::big_int::BigInt;
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
/// A big integer with the invariant that its value is less than its modulus
pub struct FieldElement(BigInt<4>);

impl FieldElement {
    const N: Self = Self(BigInt::new([
        0xffffffff00000000,
        0xffffffffffffffff,
        0xbce6faada7179e84,
        0xf3b9cac2fc632551,
    ]));
}

// We can't implement DerefMut because that would make it impossible to verify that
// `FieldElement`'s invariants are maintained
impl core::ops::Deref for FieldElement {
    type Target = BigInt<4>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
