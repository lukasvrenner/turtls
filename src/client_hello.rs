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
    pub const RANDOM_BYTES_LEN: usize = 32;

    pub fn new(sup_suites: &[CipherSuite]) -> Result<Self, Error> {
        let mut msg = Self::start();
        msg.legacy_protocol_version();
        msg.random_bytes()?;
        msg.legacy_session_id();
        msg.cipher_suites(sup_suites);
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
        self.extend_from_slice(&[0; Self::RANDOM_BYTES_LEN]);
        let len = self.len();
        getrandom(&mut self[len - Self::RANDOM_BYTES_LEN..])
    }

    fn legacy_session_id(&mut self) {
        self.push(0x00);
    }

    fn cipher_suites(&mut self, sup_suites: &[CipherSuite]) {
        let len = (sup_suites.len() as u16).to_be_bytes();
        self.extend_from_slice(&len);

        for suite in sup_suites
            .into_iter()
            .map(|suite| (*suite as u16).to_be_bytes())
        {
            self.extend_from_slice(&suite);
        }
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

pub enum CliHelloParseError {
    MissingData,
    InvalidLengthEncoding,
}

pub struct ClientHelloRef<'a> {
    pub random_bytes: &'a [u8; 32],
    pub session_id: &'a [u8],
    pub cipher_suites: &'a [u8],
    pub extensions: &'a [u8],
}

impl<'a> ClientHelloRef<'a> {
    pub fn parse(client_hello: &'a [u8]) -> Result<Self, CliHelloParseError> {
        let mut pos = size_of::<ProtocolVersion>();
        let random_bytes = <&[u8; ClientHello::RANDOM_BYTES_LEN]>::try_from(
            &client_hello[pos..][..ClientHello::RANDOM_BYTES_LEN],
        )
        .unwrap();
        pos += random_bytes.len();

        let legacy_session_id_len = client_hello[34];
        pos += 1;
        if legacy_session_id_len > 32 {
            return Err(CliHelloParseError::InvalidLengthEncoding);
        }

        let session_id = &client_hello[pos..][..legacy_session_id_len as usize];
        pos += legacy_session_id_len as usize;

        let cipher_suites_len = client_hello[pos];
        pos += 1;
        if cipher_suites_len > (1 << 16) - 2 {
            return Err(CliHelloParseError::InvalidLengthEncoding);
        }

        let cipher_suites = &client_hello[pos..][..cipher_suites_len as usize];
        pos += cipher_suites_len as usize;

        let legacy_compression_methods_len = client_hello[pos];
        pos += 1;

        if legacy_session_id_len > 0xff {
            return Err(CliHelloParseError::InvalidLengthEncoding);
        }
        pos += legacy_compression_methods_len as usize;

        let extensions = &client_hello[pos + 1..];
        Ok(Self {
            random_bytes,
            session_id,
            cipher_suites,
            extensions,
        })
    }
}
