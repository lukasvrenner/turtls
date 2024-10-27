//use crate::cipher_suites::{CipherSuite, GroupKeys, NamedGroup, NoSharedSuites};
//use crate::client_hello::ClientHelloRef;
//use crate::extensions::ExtensionType;
////use crate::handshake::{Handshake, ShakeType};
//use crate::versions::{ProtocolVersion, LEGACY_PROTO_VERS};
//use crylib::ec::{EllipticCurve, Secp256r1};
//use getrandom::{getrandom, Error};
//
//pub struct ServerHello {
//    shake: Handshake,
//}
//
//pub enum ServHelloErr {
//    RngError,
//    NoSharedVersions,
//    NoSharedSuites,
//}
//
//impl From<Error> for ServHelloErr {
//    fn from(_: Error) -> Self {
//        Self::RngError
//    }
//}
//
//impl From<NoSharedSuites> for ServHelloErr {
//    fn from(_: NoSharedSuites) -> Self {
//        Self::NoSharedSuites
//    }
//}
//
//impl From<NoSharedVersions> for ServHelloErr {
//    fn from(_: NoSharedVersions) -> Self {
//        Self::NoSharedVersions
//    }
//}
//
//impl ServerHello {
//    const RANDOM_BYTES_LEN: usize = 32;
//    pub fn new(
//        client_hello: &ClientHelloRef,
//        sup_suites: &[CipherSuite],
//    ) -> Result<Self, ServHelloErr> {
//        let mut server_hello = Self::start();
//        server_hello.legacy_protocol_version();
//        server_hello.random_bytes()?;
//        server_hello.legacy_session_id_echo(client_hello.session_id);
//        server_hello.cipher_suite(client_hello.cipher_suites, sup_suites)?;
//        server_hello.legacy_compression_method();
//        server_hello.extensions(client_hello.extensions);
//        server_hello.finish();
//        Ok(server_hello)
//    }
//
//    fn start() -> Self {
//        Self {
//            shake: Handshake::start(ShakeType::ServerHello),
//        }
//    }
//
//    fn legacy_protocol_version(&mut self) {
//        self.extend_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
//    }
//
//    fn random_bytes(&mut self) -> Result<(), Error> {
//        self.extend_from_slice(&[0; Self::RANDOM_BYTES_LEN]);
//        let len = self.len();
//        getrandom(&mut self[len - Self::RANDOM_BYTES_LEN..])
//    }
//
//    fn legacy_session_id_echo(&mut self, client_ses_id: &[u8]) {
//        self.extend_from_slice(client_ses_id);
//    }
//
//    fn cipher_suite(
//        &mut self,
//        client_cipher_suites: &[u8],
//        sup_suites: &[CipherSuite],
//    ) -> Result<(), NoSharedSuites> {
//        for suite in client_cipher_suites.chunks_exact(2) {
//            for sup_suite in sup_suites {
//                if suite == sup_suite.to_be_bytes() {
//                    self.extend_from_slice(suite);
//                    return Ok(());
//                }
//            }
//        }
//        Err(NoSharedSuites)
//    }
//
//    fn legacy_compression_method(&mut self) {
//        self.push(0x00);
//    }
//
//    fn extensions(&mut self, extensions: &[u8]) {
//        todo!();
//    }
//
//    fn supported_versions(
//        &mut self,
//        cli_supported_versions: &[u8],
//    ) -> Result<(), NoSharedVersions> {
//        let extension_name = ExtensionType::SupportedVersions.to_be_bytes();
//        self.extend_from_slice(&extension_name);
//
//        self.extend_from_slice(&(size_of::<ProtocolVersion>() as u16).to_be_bytes());
//        for cli_version in cli_supported_versions.chunks_exact(2) {
//            if cli_version == ProtocolVersion::TlsOnePointThree.to_be_bytes() {
//                self.extend_from_slice(cli_version);
//                return Ok(());
//            }
//        }
//        Err(NoSharedVersions)
//    }
//
//    fn key_share(&mut self, group_keys: &GroupKeys) {
//        let extension_name = ExtensionType::KeyShare.to_be_bytes();
//        self.extend_from_slice(&extension_name);
//
//        let original_len = self.len();
//        self.extend_from_slice(&[0; 2]);
//
//        self.secp256r1_key_share(group_keys);
//
//        let len_diff = ((self.len() - (original_len + 2)) as u16).to_be_bytes();
//        self[original_len..][..2].copy_from_slice(&len_diff);
//    }
//
//    fn secp256r1_key_share(&mut self, group_keys: &GroupKeys) {
//        let named_group = NamedGroup::Secp256r1.to_be_bytes();
//        self.extend_from_slice(&named_group);
//
//        let original_len = self.len();
//        self.extend_from_slice(&[0; 2]);
//
//        self.push(4);
//        let pub_key = Secp256r1::BASE_POINT
//            .as_projective()
//            .mul_scalar(group_keys.secp256r1.inner())
//            .as_affine()
//            .expect("private key isn't 0");
//        self.extend_from_slice(&pub_key.x().to_be_bytes());
//        self.extend_from_slice(&pub_key.y().to_be_bytes());
//
//        let len_diff = ((self.len() - (original_len + 2)) as u16).to_be_bytes();
//        self[original_len..][..2].copy_from_slice(&len_diff);
//    }
//}
//
//pub struct NoSharedVersions;
//
//impl std::ops::Deref for ServerHello {
//    type Target = Handshake;
//    fn deref(&self) -> &Self::Target {
//        &self.shake
//    }
//}
//
//impl std::ops::DerefMut for ServerHello {
//    fn deref_mut(&mut self) -> &mut Self::Target {
//        &mut self.shake
//    }
//}

//pub struct ServerHelloRef<'a> {
//    pub random_bytes: &'a [u8; 32],
//    pub cipher_suite: CipherSuite,
//    pub extensions: &'a [u8],
//}
//
//pub enum SerHelloParseError {
//    MissingData,
//    InvalidLengthEncoding,
//    InvalidCipherSuite,
//}
//
//impl<'a> ServerHelloRef<'a> {
//    fn parse(server_hello: &'a [u8]) -> Result<Self, SerHelloParseError> {
//        let mut pos = size_of::<ProtocolVersion>();
//        let random_bytes =
//            <&[u8; 32]>::try_from(&server_hello[2..][..ServerHello::RANDOM_BYTES_LEN]).unwrap();
//        pos += random_bytes.len();
//        let session_id_len = server_hello[pos];
//        pos += 1;
//        if session_id_len > 32 {
//            return Err(SerHelloParseError::InvalidLengthEncoding);
//        };
//        pos += session_id_len as usize;
//        let cipher_suite = if server_hello[pos] == CipherSuite::Aes128GcmSha256 as u8 {
//            CipherSuite::Aes128GcmSha256
//        } else {
//            return Err(SerHelloParseError::InvalidCipherSuite);
//        };
//        pos += 1;
//        let extensions = &server_hello[pos..];
//        Ok(Self {
//            random_bytes,
//            cipher_suite,
//            extensions,
//        })
//    }
//}
