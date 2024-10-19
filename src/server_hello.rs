use crate::cipher_suites::{CipherSuite, NoSharedSuites};
use crate::client_hello::ClientHelloRef;
use crate::handshake::{Handshake, ShakeType};
use crate::versions::{ProtocolVersion, LEGACY_PROTO_VERS};
use getrandom::{getrandom, Error};

pub struct ServerHello {
    shake: Handshake,
}

impl ServerHello {
    const RANDOM_BYTES_LEN: usize = 32;
    pub fn new(client_hello: &ClientHelloRef, sup_suites: &[CipherSuite]) -> Result<Self, Error> {
        let mut server_hello = Self::start();
        server_hello.legacy_protocol_version();
        server_hello.random_bytes()?;
        server_hello.legacy_session_id_echo(client_hello.session_id);
        server_hello.cipher_suite(client_hello.cipher_suites, sup_suites);
        server_hello.legacy_compression_method();
        server_hello.extensions(client_hello.extensions);
        server_hello.finish();
        Ok(server_hello)
    }

    fn start() -> Self {
        Self {
            shake: Handshake::start(ShakeType::ServerHello),
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

    fn legacy_session_id_echo(&mut self, client_ses_id: &[u8]) {
        self.extend_from_slice(client_ses_id);
    }

    fn cipher_suite(
        &mut self,
        client_cipher_suites: &[u8],
        sup_suites: &[CipherSuite],
    ) -> Result<(), NoSharedSuites> {
        self.extend_from_slice(
            &CipherSuite::sel_from_bytes(client_cipher_suites, sup_suites)?.to_be_bytes(),
        );
        Ok(())
    }

    fn legacy_compression_method(&mut self) {
        self.push(0x00);
    }

    fn extensions(&mut self, extensions: &[u8]) {
        todo!();
    }
}

impl std::ops::Deref for ServerHello {
    type Target = Handshake;
    fn deref(&self) -> &Self::Target {
        &self.shake
    }
}

impl std::ops::DerefMut for ServerHello {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.shake
    }
}

pub struct ServerHelloRef<'a> {
    pub random_bytes: &'a [u8; 32],
    pub cipher_suite: CipherSuite,
    pub extensions: &'a [u8],
}

pub enum SerHelloParseError {
    MissingData,
    InvalidLengthEncoding,
    InvalidCipherSuite,
}

impl<'a> ServerHelloRef<'a> {
    fn parse(server_hello: &'a [u8]) -> Result<Self, SerHelloParseError> {
        let mut pos = size_of::<ProtocolVersion>();
        let random_bytes = &server_hello[2..][..ServerHello::RANDOM_BYTES_LEN];
        pos += random_bytes.len();
        let session_id_len = server_hello[pos];
        pos += 1;
        if session_id_len > 32 {
            return Err(SerHelloParseError::InvalidLengthEncoding);
        };
        pos += session_id_len as usize;
        let cipher_suite = if server_hello[pos] == CipherSuite::Aes128GcmSha256 as u8 {
            CipherSuite::Aes128GcmSha256
        } else {
            return Err(SerHelloParseError::InvalidCipherSuite);
        };
        pos += 1;
        let extensions = &server_hello[pos..];
        Ok(Self {
            random_bytes,
            cipher_suite,
            extensions,
        })
    }
}
