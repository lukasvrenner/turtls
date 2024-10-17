use crate::cipher_suites::CipherSuite;
use crate::handshake::{Handshake, ShakeType};
use crate::versions::LEGACY_PROTO_VERS;
use getrandom::{getrandom, Error};
use crate::client_hello::ClientHelloRef;

pub struct ServerHello {
    shake: Handshake,
}

impl ServerHello {
    pub fn new(client_hello: &ClientHelloRef) -> Result<Self, Error> {
        let mut server_hello = Self::start();
        server_hello.legacy_protocol_version();
        server_hello.random_bytes()?;
        server_hello.legacy_session_id_echo(client_hello.session_id);
        server_hello.cipher_suite(client_hello.cipher_suites);
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
        self.extend_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
    }

    fn random_bytes(&mut self) -> Result<(), Error> {
        self.extend_from_slice(&[0; 32]);
        let len = self.len();
        getrandom(&mut self[len - 32..])
    }

    fn legacy_session_id_echo(&mut self, client_ses_id: &[u8]) {
        self.extend_from_slice(client_ses_id);
    }

    fn cipher_suite(&mut self, client_cipher_suites: &[CipherSuite]) {
        let cipher_suite: CipherSuite = todo!();
        self.push(cipher_suite as u8);
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
