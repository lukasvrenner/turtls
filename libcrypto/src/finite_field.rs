mod field_element;
mod point;

pub use field_element::FieldElement;
pub use point::Point;

use crate::big_int::UBigInt;

pub trait FiniteField
where
    Self: Sized + Copy + Clone,
{
    /// The modulus used for the finite field.
    ///
    ///
    const MODULUS: UBigInt<4>;

    const MIN: FieldElement<Self> = Self::ZERO;

    const ZERO: FieldElement<Self>;

    const ONE: FieldElement<Self>;
}
