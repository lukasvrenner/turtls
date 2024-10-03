pub const C_SUITES_PREFIX: u8 = 0x13;

#[repr(u8)]
pub enum CipherSuites {
    Aes128GcmSha256 = 1,
    Aes256GcmSha384 = 2,
    ChaCha20Poly1305Sha256 = 3,
    Aes128CcmSha256 = 4,
    Aes128Ccm8Sha256 = 5,
}
