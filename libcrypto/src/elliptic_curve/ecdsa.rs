//! The Elliptic Curve Digital Signature Algorithm.

use super::{EllipticCurve, ProjectivePoint};
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
    hash_func: impl FnOnce(&[u8]) -> [u8; 32],
    secret_num_gen: impl Fn() -> FieldElement<C>,
) -> Signature<C> {
    let mut hash: FieldElement<C> = FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));

    loop {
        let secret_num = secret_num_gen();
        let mut inverse = secret_num.inverse();

        let Some(new_point) = C::BASE_POINT
            .as_projective()
            .mul_scalar(secret_num.inner())
            .as_affine() else {
            continue
        };

        hash.add_assign(&new_point.x().mul(priv_key));
        inverse.mul_assign(&hash);

        if new_point.x_ref() != &FieldElement::ZERO && inverse != FieldElement::ZERO {
            return Signature::new(new_point.x(), inverse);
        }
    }
}

pub fn verify_signature<C: EllipticCurve>(
    msg: &[u8],
    pub_key: &ProjectivePoint<C>,
    hash_func: impl FnOnce(&[u8]) -> [u8; 32],
    sign: &Signature<C>,
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

#[cfg(test)]
mod tests {
    use crate::elliptic_curve::Secp256r1;

    use super::FieldElement;
    use super::ProjectivePoint;
    use super::Signature;
    use super::UBigInt;
    use super::ValidSign;

    // test vectors from http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip

    #[test]
    fn sign() {
        let msg = &[
            0x59, 0x05, 0x23, 0x88, 0x77, 0xc7, 0x74, 0x21, 0xf7, 0x3e, 0x43, 0xee, 0x3d, 0xa6,
            0xf2, 0xd9, 0xe2, 0xcc, 0xad, 0x5f, 0xc9, 0x42, 0xdc, 0xec, 0x0c, 0xbd, 0x25, 0x48,
            0x29, 0x35, 0xfa, 0xaf, 0x41, 0x69, 0x83, 0xfe, 0x16, 0x5b, 0x1a, 0x04, 0x5e, 0xe2,
            0xbc, 0xd2, 0xe6, 0xdc, 0xa3, 0xbd, 0xf4, 0x6c, 0x43, 0x10, 0xa7, 0x46, 0x1f, 0x9a,
            0x37, 0x96, 0x0c, 0xa6, 0x72, 0xd3, 0xfe, 0xb5, 0x47, 0x3e, 0x25, 0x36, 0x05, 0xfb,
            0x1d, 0xdf, 0xd2, 0x80, 0x65, 0xb5, 0x3c, 0xb5, 0x85, 0x8a, 0x8a, 0xd2, 0x81, 0x75,
            0xbf, 0x9b, 0xd3, 0x86, 0xa5, 0xe4, 0x71, 0xea, 0x7a, 0x65, 0xc1, 0x7c, 0xc9, 0x34,
            0xa9, 0xd7, 0x91, 0xe9, 0x14, 0x91, 0xeb, 0x37, 0x54, 0xd0, 0x37, 0x99, 0x79, 0x0f,
            0xe2, 0xd3, 0x08, 0xd1, 0x61, 0x46, 0xd5, 0xc9, 0xb0, 0xd0, 0xde, 0xbd, 0x97, 0xd7,
            0x9c, 0xe8,
        ];

        let priv_key = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0xca54a56dda72b464,
                0x5b44c8130b4e3eac,
                0x1f4fa8ee59f4771a,
                0x519b423d715f8b58,
            ]))
        };

        let r = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0xcabb5e6f79c8c2ac,
                0x2afd6b1f6a555a7a,
                0x8843e3d6629527ed,
                0xf3ac8061b514795b,
            ]))
        };

        let s = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0x3ccdda2acc058903,
                0xef97b218e96f175a,
                0x786c76262bf7371c,
                0x8bf77819ca05a6b2,
            ]))
        };
        let signature = Signature::new(r, s);

        let super_secure_secret_num_generator = || unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0xb9670787642a68de,
                0x3b4a6247824f5d33,
                0xa280f245f9e93c7f,
                0x94a1bbb14b906a61,
            ]))
        };

        let generated_signature = super::sign(
            msg,
            &priv_key,
            crate::sha2::sha256,
            super_secure_secret_num_generator,
        );
        assert_eq!(generated_signature, signature);
    }

    #[test]
    fn verify_signature() {
        let msg = &[
            0x59, 0x05, 0x23, 0x88, 0x77, 0xc7, 0x74, 0x21, 0xf7, 0x3e, 0x43, 0xee, 0x3d, 0xa6,
            0xf2, 0xd9, 0xe2, 0xcc, 0xad, 0x5f, 0xc9, 0x42, 0xdc, 0xec, 0x0c, 0xbd, 0x25, 0x48,
            0x29, 0x35, 0xfa, 0xaf, 0x41, 0x69, 0x83, 0xfe, 0x16, 0x5b, 0x1a, 0x04, 0x5e, 0xe2,
            0xbc, 0xd2, 0xe6, 0xdc, 0xa3, 0xbd, 0xf4, 0x6c, 0x43, 0x10, 0xa7, 0x46, 0x1f, 0x9a,
            0x37, 0x96, 0x0c, 0xa6, 0x72, 0xd3, 0xfe, 0xb5, 0x47, 0x3e, 0x25, 0x36, 0x05, 0xfb,
            0x1d, 0xdf, 0xd2, 0x80, 0x65, 0xb5, 0x3c, 0xb5, 0x85, 0x8a, 0x8a, 0xd2, 0x81, 0x75,
            0xbf, 0x9b, 0xd3, 0x86, 0xa5, 0xe4, 0x71, 0xea, 0x7a, 0x65, 0xc1, 0x7c, 0xc9, 0x34,
            0xa9, 0xd7, 0x91, 0xe9, 0x14, 0x91, 0xeb, 0x37, 0x54, 0xd0, 0x37, 0x99, 0x79, 0x0f,
            0xe2, 0xd3, 0x08, 0xd1, 0x61, 0x46, 0xd5, 0xc9, 0xb0, 0xd0, 0xde, 0xbd, 0x97, 0xd7,
            0x9c, 0xe8,
        ];

        let pub_key_x = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0x3c59ff46c271bf83,
                0xd3565de94bbfb12f,
                0xf033bfa248db8fcc,
                0x1ccbe91c075fc7f4,
            ]))
        };

        let pub_key_y = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0xdc7ccd5ca89a4ca9,
                0x6db7ca93b7404e78,
                0x1a1fdb2c0e6113e0,
                0xce4014c68811f9a2,
            ]))
        };

        let pub_key =
            unsafe { ProjectivePoint::new_unchecked(pub_key_x, pub_key_y, FieldElement::ONE) };

        let r = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0xcabb5e6f79c8c2ac,
                0x2afd6b1f6a555a7a,
                0x8843e3d6629527ed,
                0xf3ac8061b514795b,
            ]))
        };

        let s = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0x3ccdda2acc058903,
                0xef97b218e96f175a,
                0x786c76262bf7371c,
                0x8bf77819ca05a6b2,
            ]))
        };
        let signature = Signature::new(r, s);

        assert_eq!(
            super::verify_signature(msg, &pub_key, crate::sha2::sha256, &signature),
            Ok(ValidSign)
        );
    }
}
