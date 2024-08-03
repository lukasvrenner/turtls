mod field_element;
mod point;

pub use field_element::FieldElement;
pub use point::Point;

pub trait FiniteField
where
    Self: Sized + Copy + Clone,
{
    /// The modulus used for the finite field.
    ///
    ///
    const MODULUS: FieldElement<Self>;

    const MIN: FieldElement<Self> = Self::ZERO;

    const ZERO: FieldElement<Self>;

    const ONE: FieldElement<Self>;
}
