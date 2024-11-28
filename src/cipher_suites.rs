use crate::record::IoError;
use crate::record::RecordLayer;

/// The supported ciphersuites.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CipherList {
    pub(crate) suites: u8,
}

impl CipherList {
    /// AES-128 GCM with SHA-256.
    ///
    /// Use this unless *UTMOST* security is needed.
    pub const AES_128_GCM_SHA256: u8 = 0b00000001;
    /// ChaCha20 Poly1305 with SHA-256.
    ///
    /// This is a good option. You should probably leave it enabled.
    pub const CHA_CHA_POLY1305_SHA256: u8 = 0b00000010;

    pub(crate) const LEN_SIZE: usize = 2;

    pub(crate) const fn len(&self) -> usize {
        self.suites.count_ones() as usize * size_of::<CipherSuite>()
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) -> Result<(), IoError> {
        if self.suites & Self::AES_128_GCM_SHA256 > 0 {
            record_layer.push_u16(CipherSuite::Aes128GcmSha256.as_int())?;
        }
        if self.suites & Self::CHA_CHA_POLY1305_SHA256 > 0 {
            record_layer.push_u16(CipherSuite::ChaCha20Poly1305Sha256.as_int())?;
        }
        Ok(())
    }

    pub(crate) fn parse_singular(suite: [u8; size_of::<CipherSuite>()]) -> Self {
        // fill in more values once more ciphersuites are supported
        match suite {
            x if x == CipherSuite::Aes128GcmSha256.as_int().to_be_bytes() => Self {
                suites: Self::AES_128_GCM_SHA256,
            },
            x if x == CipherSuite::Aes256GcmSha384.as_int().to_be_bytes() => Self { suites: 0 },
            x if x == CipherSuite::ChaCha20Poly1305Sha256.as_int().to_be_bytes() => Self {
                suites: Self::CHA_CHA_POLY1305_SHA256,
            },
            x if x == CipherSuite::Aes128CcmSha256.as_int().to_be_bytes() => Self { suites: 0 },
            x if x == CipherSuite::Aes128Ccm8Sha256.as_int().to_be_bytes() => Self { suites: 0 },
            _ => Self { suites: 0 },
        }
    }
}

impl Default for CipherList {
    fn default() -> Self {
        Self {
            suites: Self::AES_128_GCM_SHA256 | Self::CHA_CHA_POLY1305_SHA256,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum CipherSuite {
    Aes128GcmSha256 = 0x1301,
    Aes256GcmSha384 = 0x1302,
    ChaCha20Poly1305Sha256 = 0x1303,
    Aes128CcmSha256 = 0x1304,
    Aes128Ccm8Sha256 = 0x1305,
}

impl CipherSuite {
    pub(crate) const fn as_int(self) -> u16 {
        self as u16
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        self.as_int().to_be_bytes()
    }
}

pub(crate) struct NoSharedSuites;

#[repr(u16)]
pub(crate) enum SignatureScheme {
    RsaPkcs1Sha256 = 0x401,
    RsaPkcs1Sha384 = 0x501,
    RsaPkcs1Sha512 = 0x601,

    EcdsaSecp256r1Sha256 = 0x403,
    EcdsaSecp384r1Sha384 = 0x503,
    EcdsaSecp512r1Sha512 = 0x603,

    RsaPssRsaeSha256 = 0x804,
    RsaPssRsaeSha384 = 0x805,
    RsaPssRsaeSha512 = 0x806,

    Ed25519 = 0x807,
    Ed448 = 0x808,

    RsaPssPssSha256 = 0x809,
    RsaPssPssSha384 = 0x80a,
    RsaPssPssSha512 = 0x80b,

    RsaPkcs1Sha1 = 0x201,
    EcdsaSha1 = 0x203,
}

impl SignatureScheme {
    pub(crate) const fn as_int(self) -> u16 {
        self as u16
    }
    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        self.as_int().to_be_bytes()
    }
}
