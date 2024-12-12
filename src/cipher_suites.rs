use crate::handshake::ShakeBuf;

/// The supported ciphersuites.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CipherList {
    pub(crate) suites: u8,
}

impl CipherList {
    /// ChaCha20 Poly1305 with SHA-256.
    ///
    /// This is a good option. You should probably leave it enabled.
    pub const CHA_CHA_POLY1305_SHA256: u8 = 0b00000001;

    /// AES-128 GCM with SHA-256.
    ///
    /// Hardware instructions are *not* yet supported.
    ///
    /// This is a good option. You should probably leave it enabled.
    pub const AES_128_GCM_SHA256: u8 = 0b00000010;

    pub(crate) const LEN_SIZE: usize = 2;

    pub(crate) const fn len(&self) -> usize {
        self.suites.count_ones() as usize * size_of::<CipherSuite>()
    }

    pub(crate) fn write_to(&self, buf: &mut ShakeBuf) {
        if self.suites & Self::CHA_CHA_POLY1305_SHA256 > 0 {
            buf.extend_from_slice(&CipherSuite::ChaCha20Poly1305Sha256.to_be_bytes());
        }
        if self.suites & Self::AES_128_GCM_SHA256 > 0 {
            buf.extend_from_slice(&CipherSuite::Aes128GcmSha256.to_be_bytes());
        }
    }

    pub(crate) fn parse_singular(suite: [u8; size_of::<CipherSuite>()]) -> Self {
        // fill in more values once more ciphersuites are supported
        match suite {
            x if x == CipherSuite::Aes128GcmSha256.as_int().to_be_bytes() => Self {
                suites: Self::AES_128_GCM_SHA256,
            },
            x if x == CipherSuite::ChaCha20Poly1305Sha256.as_int().to_be_bytes() => Self {
                suites: Self::CHA_CHA_POLY1305_SHA256,
            },
            _ => Self { suites: 0 },
        }
    }
}

impl Default for CipherList {
    fn default() -> Self {
        Self {
            suites: Self::CHA_CHA_POLY1305_SHA256 | Self::AES_128_GCM_SHA256,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum CipherSuite {
    Aes128GcmSha256 = 0x1301,
    #[expect(unused, reason = "AES_256_GCM_SHA384 is not supported")]
    Aes256GcmSha384 = 0x1302,
    ChaCha20Poly1305Sha256 = 0x1303,
    #[expect(unused, reason = "AES_128_CCM_SHA256 is not supported")]
    Aes128CcmSha256 = 0x1304,
    #[expect(unused, reason = "AES_128_CCM8_SHA256 is not supported")]
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
