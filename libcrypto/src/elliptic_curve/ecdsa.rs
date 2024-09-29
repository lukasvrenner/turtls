//! The Elliptic Curve Digital Signature Algorithm.

use super::{AffinePoint, EllipticCurve, ProjectivePoint};
use crate::big_int::UBigInt;
use crate::finite_field::FieldElement;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Signature<C: EllipticCurve> {
    r: FieldElement<C>,
    s: FieldElement<C>,
}

impl<C: EllipticCurve> Signature<C> {
    pub const fn new(r: FieldElement<C>, s: FieldElement<C>) -> Self {
        Self { r, s }
    }
}

/// The value that represents a valid signature.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct ValidSign;

impl core::fmt::Display for ValidSign {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the signature is valid")
    }
}

/// The error that represents an invalid signature.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct InvalidSign;

impl core::fmt::Display for InvalidSign {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the signature is not valid")
    }
}

impl core::error::Error for InvalidSign {}

pub fn sign<C: EllipticCurve>(
    msg: &[u8],
    priv_key: &FieldElement<C>,
    hash_func: fn(&[u8]) -> [u8; 32],
    secret_num_gen: impl Fn() -> FieldElement<C>,
) -> Signature<C> {
    let mut hash: FieldElement<C> = FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));
    let mut secret_num;
    let mut inverse;
    let mut new_point;

    loop {
        secret_num = secret_num_gen();
        inverse = secret_num.inverse();

        new_point = C::BASE_POINT
            .as_projective()
            .mul_scalar(secret_num.inner())
            .as_affine()
            .unwrap();

        hash.add_assign(&new_point.x().mul(priv_key));
        inverse.mul_assign(&hash);
        if new_point.x_ref() != &FieldElement::ZERO && inverse != FieldElement::ZERO {
            break;
        }
    }

    // TODO: destroy secret_num
    Signature::new(new_point.x(), inverse)
}

pub fn verify_signature<C: EllipticCurve>(
    msg: &[u8],
    pub_key: &ProjectivePoint<C>,
    hash_func: fn(&[u8]) -> [u8; 32],
    sign: Signature<C>,
) -> Result<ValidSign, InvalidSign> {
    let hash: FieldElement<C> = FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));
    let inverse = sign.s.inverse();

    let u = hash.mul(&inverse);
    let v = sign.r.mul(&inverse);

    let r = match C::BASE_POINT
        .as_projective()
        .mul_scalar(&u.inner())
        .add(&pub_key.mul_scalar(v.inner()))
        .as_affine()
    {
        Some(point) => point.x(),
        None => return Err(InvalidSign),
    };
    match r == sign.r {
        true => Ok(ValidSign),
        false => Err(InvalidSign),
    }

}
