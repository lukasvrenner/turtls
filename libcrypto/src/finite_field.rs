//! Finite field arithmetic.
mod field_element;

pub use field_element::FieldElement;

use crate::big_int::UBigInt;

/// A trait for describing a finite field.
///
/// # Safety
/// [`Self::MODULUS`] *MUST* be prime.
/// Using a non-prime number will result in undefined behavior.
pub unsafe trait FiniteField
where
    Self: Sized
{
    /// The modulus used to define the finite field.
    ///
    /// This value *MUST* be prime.
    /// Using a non-prime number will result in undefined behavior.
    const MODULUS: UBigInt<4>;

    /// The smallest value in the finite field.
    const MIN: FieldElement<Self> = Self::ZERO;

    /// The field element of value `0`.
    const ZERO: FieldElement<Self>;

    /// The field element of value `1`.
    const ONE: FieldElement<Self>;
}
