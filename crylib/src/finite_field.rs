//! Finite field arithmetic.
mod field_element;

pub use field_element::FieldElement;

use crate::big_int::UBigInt;

/// A trait for describing a finite field.
///
/// # Safety
/// `MODULUS` *MUST* be prime.
pub unsafe trait FiniteField<const N: usize>
where
    Self: Sized + PartialEq + Copy + Clone + core::fmt::Debug,
{
    /// The modulus used to define the finite field.
    ///
    /// This value *MUST* be prime.
    /// Using a non-prime number will result in undefined behavior.
    const MODULUS: UBigInt<N>;

    /// The smallest value in the finite field.
    const MIN: FieldElement<N, Self> = FieldElement::ZERO;
}
