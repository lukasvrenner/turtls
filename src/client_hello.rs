use crate::cipher_suites::CipherSuite;
use crate::extensions;
use crate::handshake::Handshake;
use crate::handshake::ShakeType;
use crate::versions::ProtocolVersion;
use crate::versions::LEGACY_PROTO_VERS;
use getrandom::{getrandom, Error};

pub struct ClientHello {
    shake: Handshake,
}

impl ClientHello {
    pub fn new() -> Result<Self, Error> {
        let mut msg = Self::start();
        msg.legacy_protocol_version();
        msg.random_bytes()?;
        msg.legacy_session_id();
        msg.cipher_suites();
        msg.legacy_compression_methods();
        msg.extensions();
        msg.finish();
        Ok(msg)
    }

    fn start() -> Self {
        Self {
            shake: Handshake::start(ShakeType::ClientHello),
        }
    }

    fn legacy_protocol_version(&mut self) {
        self.extend_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
    }

    fn random_bytes(&mut self) -> Result<(), Error> {
        self.extend_from_slice(&[0; 32]);
        let len = self.len();
        getrandom(&mut self[len - 32..])
    }

    fn legacy_session_id(&mut self) {
        self.push(0x00);
    }

    fn cipher_suites(&mut self) {
        let len = 1u16.to_be_bytes();
        self.extend_from_slice(&len);

        let aes128_gcm_sha256 = CipherSuite::Aes128GcmSha256.to_be_bytes();
        self.extend_from_slice(&aes128_gcm_sha256);
    }

    fn legacy_compression_methods(&mut self) {
        self.push(0x00);
    }

    fn extensions(&mut self) {
        self.extend_from_slice(&[0, 0]);
        let original_len = self.len();

        extensions::supported_groups(self);
        extensions::signature_algorithms(self);
        extensions::supported_versions_client(self);
        extensions::supported_groups(self);

        let extensions_len = ((original_len - self.len()) as u16).to_be_bytes();
        self[original_len - 2..][..2].copy_from_slice(&extensions_len);
    }
}

impl std::ops::Deref for ClientHello {
    type Target = Handshake;
    fn deref(&self) -> &Self::Target {
        &self.shake
    }
}

impl std::ops::DerefMut for ClientHello {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.shake
    }
}

pub struct ClientHelloRef<'a> {
    pub proto_version: ProtocolVersion,
    pub random_bytes: &'a [u8; 32],
    pub session_id: &'a [u8],
    pub cipher_suites: &'a [CipherSuite],
    pub compression_methods: &'a [u8],
    pub extensions: &'a [u8],
}
