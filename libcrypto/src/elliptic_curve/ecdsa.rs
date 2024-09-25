use super::EllipticCurve;
use crate::big_int::UBigInt;
use crate::finite_field::FieldElement;

pub fn generate_signature<C: EllipticCurve>(
    msg: &[u8],
    key: FieldElement<C>,
    hash_func: fn(&[u8]) -> [u8; 32],
    secret_num: FieldElement<C>,
) -> (FieldElement<C>, FieldElement<C>) {
    let hash: FieldElement<C> = FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));
    let inverse = secret_num.inverse();

    let new_point = C::BASE_POINT
        .as_projective()
        .mul_scalar(secret_num.into_inner())
        .as_affine();

    let s = inverse.mul(&(hash.add(&(new_point.x().mul(&key)))));

    // TODO: destroy inverse

    (*new_point.x(), s)
}
