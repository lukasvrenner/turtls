use crate::big_int::UBigInt;
use crate::finite_field::{FieldElement, FiniteField, Point};
pub fn generate_signature<F: FiniteField>(
    msg: &[u8],
    key: FieldElement<F>,
    hash_func: fn(&[u8]) -> [u8; 32],
    secret_num: FieldElement<F>,
) -> (FieldElement<F>, FieldElement<F>) {
    let hash: FieldElement<F> = FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));
    let inverse = secret_num.inverse();

    let new_point = Point::G.mul_scalar(secret_num);

    let s = inverse.mul(&(hash.add(&(new_point.0.mul(&key)))));

    // TODO: destroy inverse

    (new_point.0, s)
}
