use crate::big_int::BigInt;
use crate::elliptic_curve::secp256r1::{FieldElement, Point};
pub fn generate_signature(
    msg: &[u8],
    key: FieldElement,
    hash_func: fn(&[u8]) -> [u8; 32],
    secret_num: FieldElement,
) -> (FieldElement, FieldElement) {
    let hash: FieldElement = BigInt::from_be_bytes(hash_func(msg)).into();
    let inverse = secret_num.inverse();

    let new_point = Point::G.mul_scalar(secret_num);

    let s = inverse * (hash + new_point.0 * key);

    // TODO: destroy inverse

    (new_point.0, s)

}
