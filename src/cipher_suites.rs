use crylib::{
    ec::{EllipticCurve, Secp256r1},
    finite_field::FieldElement,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum CipherSuite {
    Aes128GcmSha256 = 0x1301,
    Aes256GcmSha384 = 0x1302,
    ChaCha20Poly1305Sha256 = 0x1303,
    Aes128CcmSha256 = 0x1304,
    Aes128Ccm8Sha256 = 0x1305,
}

impl CipherSuite {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

pub struct NoSharedSuites;

#[repr(u16)]
pub enum NamedGroup {
    Secp256r1 = 0x17,
    Secp384r1 = 0x18,
    Secp521r1 = 0x19,

    X25519 = 0x1d,
    X448 = 0x1e,

    Ffdhe2048 = 0x100,
    Ffdhe3072 = 0x101,
    Ffdhe4096 = 0x102,
    Ffdhe6144 = 0x103,
    Ffdhe8192 = 0x104,
}

impl NamedGroup {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

pub struct GroupKeys {
    pub secp256r1: FieldElement<<Secp256r1 as EllipticCurve>::Order>,
}

#[repr(u16)]
pub enum SignatureScheme {
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
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}
