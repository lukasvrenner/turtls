//! The Elliptic Curve Digital Signature Algorithm.

use super::{EllipticCurve, ProjectivePoint};
use crate::big_int::UBigInt;
use crate::finite_field::{FieldElement, FiniteField};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Signature<C: FiniteField> {
    r: FieldElement<C>,
    s: FieldElement<C>,
}

impl<C: FiniteField> Signature<C> {
    pub const fn new(r: FieldElement<C>, s: FieldElement<C>) -> Self {
        Self { r, s }
    }
}

/// The value that represents a valid signature.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct ValidSig;

impl core::fmt::Display for ValidSig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the signature is valid")
    }
}

/// The error that represents an invalid signature.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct InvalidSig;

impl core::fmt::Display for InvalidSig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the signature is not valid")
    }
}

impl core::error::Error for InvalidSig {}

/// Creates a unique signature for `msg`.
///
/// Both parties must use the same `hash_func` (such as SHA-256) for signing and signature authentication.
/// Additionally, `priv_key` must be the private key that corresponds to the shared public key.
///
/// DO NOT SHARE THE PRIVATE KEY. The security of this algorithm depends on the secrecy of
/// `priv_key`.
pub fn sign<C: EllipticCurve>(
    msg: &[u8],
    priv_key: &FieldElement<C::Order>,
    hash_func: impl FnOnce(&[u8]) -> [u8; 32],
    random_num_gen: impl Fn() -> FieldElement<C::Order>,
) -> Signature<C::Order> {
    let mut hash: FieldElement<C::Order> =
        FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));

    loop {
        let secret_num = random_num_gen();
        let mut inverse = secret_num.inverse();

        let Some(new_point) = C::BASE_POINT
            .mul_scalar(&secret_num)
            .as_affine()
        else {
            continue;
        };

        let r = new_point.x_ref().convert();

        hash.add_assign(&r.mul(priv_key));
        inverse.mul_assign(&hash);

        if r != FieldElement::ZERO && inverse != FieldElement::ZERO {
            return Signature::new(r, inverse);
        }
    }
}

/// Verifies the authenticity of `sig` using the signer's public key.
pub fn verify_signature<C: EllipticCurve>(
    msg: &[u8],
    pub_key: &ProjectivePoint<C>,
    hash_func: impl FnOnce(&[u8]) -> [u8; 32],
    sig: &Signature<C::Order>,
) -> Result<ValidSig, InvalidSig> {
    let hash: FieldElement<C::Order> =
        FieldElement::new(UBigInt::<4>::from_be_bytes(hash_func(msg)));
    let inverse = sig.s.inverse();

    let u = hash.mul(&inverse);
    let v = sig.r.mul(&inverse);

    let r = match C::BASE_POINT
        .mul_scalar(&u)
        .add(&pub_key.mul_scalar(&v))
        .as_affine()
    {
        Some(point) => point.x_ref().convert(),
        None => return Err(InvalidSig),
    };

    match r == sig.r {
        true => Ok(ValidSig),
        false => Err(InvalidSig),
    }
}

#[cfg(test)]
mod tests {
    use crate::ec::Secp256r1;

    use super::FieldElement;
    use super::InvalidSig;
    use super::ProjectivePoint;
    use super::Signature;
    use super::UBigInt;
    use super::ValidSig;
    use crate::hash::{Hasher, Sha256};

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
            FieldElement::new_unchecked(UBigInt([
                0xca54a56dda72b464,
                0x5b44c8130b4e3eac,
                0x1f4fa8ee59f4771a,
                0x519b423d715f8b58,
            ]))
        };

        let r = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0xcabb5e6f79c8c2ac,
                0x2afd6b1f6a555a7a,
                0x8843e3d6629527ed,
                0xf3ac8061b514795b,
            ]))
        };

        let s = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x3ccdda2acc058903,
                0xef97b218e96f175a,
                0x786c76262bf7371c,
                0x8bf77819ca05a6b2,
            ]))
        };
        let signature = Signature::new(r, s);

        let super_secure_random_num_generator = || unsafe {
            FieldElement::new_unchecked(UBigInt([
                0xb9670787642a68de,
                0x3b4a6247824f5d33,
                0xa280f245f9e93c7f,
                0x94a1bbb14b906a61,
            ]))
        };

        let generated_signature = super::sign::<Secp256r1>(
            msg,
            &priv_key,
            crate::hash::Sha256::hash,
            super_secure_random_num_generator,
        );
        assert_eq!(generated_signature, signature);

        let msg = &[
            0xc3, 0x5e, 0x2f, 0x09, 0x25, 0x53, 0xc5, 0x57, 0x72, 0x92, 0x6b, 0xdb, 0xe8, 0x7c,
            0x97, 0x96, 0x82, 0x7d, 0x17, 0x02, 0x4d, 0xbb, 0x92, 0x33, 0xa5, 0x45, 0x36, 0x6e,
            0x2e, 0x59, 0x87, 0xdd, 0x34, 0x4d, 0xeb, 0x72, 0xdf, 0x98, 0x71, 0x44, 0xb8, 0xc6,
            0xc4, 0x3b, 0xc4, 0x1b, 0x65, 0x4b, 0x94, 0xcc, 0x85, 0x6e, 0x16, 0xb9, 0x6d, 0x7a,
            0x82, 0x1c, 0x8e, 0xc0, 0x39, 0xb5, 0x03, 0xe3, 0xd8, 0x67, 0x28, 0xc4, 0x94, 0xa9,
            0x67, 0xd8, 0x30, 0x11, 0xa0, 0xe0, 0x90, 0xb5, 0xd5, 0x4c, 0xd4, 0x7f, 0x4e, 0x36,
            0x6c, 0x09, 0x12, 0xbc, 0x80, 0x8f, 0xbb, 0x2e, 0xa9, 0x6e, 0xfa, 0xc8, 0x8f, 0xb3,
            0xeb, 0xec, 0x93, 0x42, 0x73, 0x8e, 0x22, 0x5f, 0x7c, 0x7c, 0x2b, 0x01, 0x1c, 0xe3,
            0x75, 0xb5, 0x66, 0x21, 0xa2, 0x06, 0x42, 0xb4, 0xd3, 0x6e, 0x06, 0x0d, 0xb4, 0x52,
            0x4a, 0xf1,
        ];

        let priv_key = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0xc201537b85479813,
                0x9a25aaf48ebb519a,
                0x5c500064824bed99,
                0x0f56db78ca460b05,
            ]))
        };

        let super_secure_random_num_generator = || unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x421187ae0b2f34c6,
                0xfb728068d3ae9fac,
                0x56bb14e0ab184aa9,
                0x6d3e71882c3b83b1,
            ]))
        };

        let r = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x6473b6a11079b2db,
                0x53f42864f508483a,
                0xc0baa9fa560b7c4e,
                0x976d3a4e9d23326d,
            ]))
        };

        let s = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x55b8eeefe36e1932,
                0x4cfa652ae5017d45,
                0x01dcd46e0af462cd,
                0x1b766e9ceb71ba6c,
            ]))
        };
        let signature = Signature::new(r, s);

        let generated_signature = super::sign::<Secp256r1>(
            msg,
            &priv_key,
            Sha256::hash,
            super_secure_random_num_generator,
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
            FieldElement::new_unchecked(UBigInt([
                0xcabb5e6f79c8c2ac,
                0x2afd6b1f6a555a7a,
                0x8843e3d6629527ed,
                0xf3ac8061b514795b,
            ]))
        };

        let s = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x3ccdda2acc058903,
                0xef97b218e96f175a,
                0x786c76262bf7371c,
                0x8bf77819ca05a6b2,
            ]))
        };
        let signature = Signature::new(r, s);

        assert_eq!(
            super::verify_signature(msg, &pub_key, Sha256::hash, &signature),
            Ok(ValidSig)
        );

        // flip one bit from original message
        let msg = &[
            0x58, 0x05, 0x23, 0x88, 0x77, 0xc7, 0x74, 0x21, 0xf7, 0x3e, 0x43, 0xee, 0x3d, 0xa6,
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

        assert_eq!(
            super::verify_signature(msg, &pub_key, Sha256::hash, &signature),
            Err(InvalidSig)
        );

        let msg = &[
            0xc3, 0x5e, 0x2f, 0x09, 0x25, 0x53, 0xc5, 0x57, 0x72, 0x92, 0x6b, 0xdb, 0xe8, 0x7c,
            0x97, 0x96, 0x82, 0x7d, 0x17, 0x02, 0x4d, 0xbb, 0x92, 0x33, 0xa5, 0x45, 0x36, 0x6e,
            0x2e, 0x59, 0x87, 0xdd, 0x34, 0x4d, 0xeb, 0x72, 0xdf, 0x98, 0x71, 0x44, 0xb8, 0xc6,
            0xc4, 0x3b, 0xc4, 0x1b, 0x65, 0x4b, 0x94, 0xcc, 0x85, 0x6e, 0x16, 0xb9, 0x6d, 0x7a,
            0x82, 0x1c, 0x8e, 0xc0, 0x39, 0xb5, 0x03, 0xe3, 0xd8, 0x67, 0x28, 0xc4, 0x94, 0xa9,
            0x67, 0xd8, 0x30, 0x11, 0xa0, 0xe0, 0x90, 0xb5, 0xd5, 0x4c, 0xd4, 0x7f, 0x4e, 0x36,
            0x6c, 0x09, 0x12, 0xbc, 0x80, 0x8f, 0xbb, 0x2e, 0xa9, 0x6e, 0xfa, 0xc8, 0x8f, 0xb3,
            0xeb, 0xec, 0x93, 0x42, 0x73, 0x8e, 0x22, 0x5f, 0x7c, 0x7c, 0x2b, 0x01, 0x1c, 0xe3,
            0x75, 0xb5, 0x66, 0x21, 0xa2, 0x06, 0x42, 0xb4, 0xd3, 0x6e, 0x06, 0x0d, 0xb4, 0x52,
            0x4a, 0xf1,
        ];

        let r = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x6473b6a11079b2db,
                0x53f42864f508483a,
                0xc0baa9fa560b7c4e,
                0x976d3a4e9d23326d,
            ]))
        };

        let s = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x55b8eeefe36e1932,
                0x4cfa652ae5017d45,
                0x01dcd46e0af462cd,
                0x1b766e9ceb71ba6c,
            ]))
        };
        let signature = Signature::new(r, s);

        let pub_key_x = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0x0bf3d4012aeffa8a,
                0x2c416044f2d2b8c1,
                0x30d4ca3e8f774943,
                0xe266ddfdc12668db,
            ]))
        };

        let pub_key_y = unsafe {
            FieldElement::<Secp256r1>::new_unchecked(UBigInt([
                0x6928973ab5b1cb39,
                0xf456b863b4d02cfc,
                0x7d47c587ef7a97a7,
                0xbfa86404a2e9ffe6,
            ]))
        };

        let pub_key =
            unsafe { ProjectivePoint::new_unchecked(pub_key_x, pub_key_y, FieldElement::ONE) };

        assert_eq!(
            super::verify_signature(msg, &pub_key, Sha256::hash, &signature),
            Ok(ValidSig)
        );

        // flip one bit in the signature
        let r = unsafe {
            FieldElement::new_unchecked(UBigInt([
                0x7473b6a11079b2db,
                0x53f42864f508483a,
                0xc0baa9fa560b7c4e,
                0x976d3a4e9d23326d,
            ]))
        };

        let signature = Signature::new(r, s);
        assert_eq!(
            super::verify_signature(msg, &pub_key, Sha256::hash, &signature),
            Err(InvalidSig)
        );
    }
}
