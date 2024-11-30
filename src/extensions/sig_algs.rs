//! The signature_algorithms and supported_groups extensions.
use super::{ExtList, ExtensionType};
use crate::record::{IoError, RecordLayer};

#[repr(u16)]
pub(crate) enum SignatureScheme {
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPkcs1Sha256 = 0x401,
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPkcs1Sha384 = 0x501,
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPkcs1Sha512 = 0x601,

    EcdsaSecp256r1Sha256 = 0x403,
    #[expect(unused, reason = "Secp384r1 is not yet supported")]
    EcdsaSecp384r1Sha384 = 0x503,
    #[expect(unused, reason = "Secp512r1 is not yet supported")]
    EcdsaSecp512r1Sha512 = 0x603,

    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPssRsaeSha256 = 0x804,
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPssRsaeSha384 = 0x805,
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPssRsaeSha512 = 0x806,

    #[expect(unused, reason = "ED25519 is not yet supported")]
    Ed25519 = 0x807,
    #[expect(unused, reason = "ED448 is not yet supported")]
    Ed448 = 0x808,

    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPssPssSha256 = 0x809,
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPssPssSha384 = 0x80a,
    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPssPssSha512 = 0x80b,

    #[expect(unused, reason = "RSA is not yet supported")]
    RsaPkcs1Sha1 = 0x201,
    #[expect(unused, reason = "SHA-1 is not supported")]
    EcdsaSha1 = 0x203,
}

impl SignatureScheme {
    pub(crate) const fn as_int(self) -> u16 {
        self as u16
    }
}

/// The ECDSA signature algoritm over the secp256r1 (NIST-P 256) curve.
pub const ECDSA_SECP256R1: u16 = 0b0000000000000001;

impl ExtList {
    pub(super) const fn sig_algs_len(&self) -> usize {
        self.sig_algs.count_ones() as usize * size_of::<SignatureScheme>() + Self::LEN_SIZE
    }

    pub(super) fn write_sig_algs(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        if self.sig_algs == 0 {
            return Ok(());
        }
        let len = self.sig_algs_len() as u16;
        rl.push_u16(ExtensionType::SignatureAlgorithms.as_int())?;
        rl.push_u16(len)?;

        rl.push_u16(len - Self::LEN_SIZE as u16)?;
        if self.sig_algs & ECDSA_SECP256R1 > 0 {
            rl.push_u16(SignatureScheme::EcdsaSecp256r1Sha256.as_int())?;
        }
        Ok(())
    }
}
