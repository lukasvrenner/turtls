//! Finite field arithmetic.
mod field_element;

pub use field_element::FieldElement;

use crate::big_int::UBigInt;

/// A trait for describing a finite field.
pub trait FiniteField
where
    Self: Sized + Copy + Clone,
{
    /// The modulus used to define the finite field.
    const MODULUS: UBigInt<4>;

    /// The smallest value in the finite field.
    const MIN: FieldElement<Self> = Self::ZERO;

    const ZERO: FieldElement<Self>;

    const ONE: FieldElement<Self>;
}
