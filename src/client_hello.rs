use crate::cipher_suites::{CipherSuite, GroupKeys, NamedGroup, SignatureScheme};
use crate::extensions::Extension;
use crate::handshake::Handshake;
use crate::handshake::ShakeType;
use crate::versions::ProtocolVersion;
use crate::versions::LEGACY_PROTO_VERS;
use crate::State;
use crylib::ec::{EllipticCurve, Secp256r1};
use getrandom::{getrandom, Error};

pub struct ClientHello {
    shake: Handshake,
}

impl ClientHello {
    pub const RANDOM_BYTES_LEN: usize = 32;

    pub fn new(sup_suites: &[CipherSuite], group_keys: &GroupKeys) -> Result<Self, Error> {
        let mut msg = Self::start();
        msg.legacy_protocol_version();
        msg.random_bytes()?;
        msg.legacy_session_id();
        msg.cipher_suites(sup_suites);
        msg.legacy_compression_methods();
        msg.extensions(group_keys);
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

    fn extensions(&mut self, group_keys: &GroupKeys) {
        self.extend_from_slice(&[0, 0]);
        let original_len = self.len();

        self.supported_versions();
        self.supported_groups();
        self.signature_algorithms();
        self.key_share(group_keys);

        let extensions_len = ((original_len - self.len()) as u16).to_be_bytes();
        self[original_len - 2..][..2].copy_from_slice(&extensions_len);
    }

    fn supported_versions(&mut self) {
        let extension_name = Extension::SupportedVersions.to_be_bytes();
        self.extend_from_slice(&extension_name);

        let extension_len = (size_of::<u8>() as u16 + 1).to_be_bytes();
        self.extend_from_slice(&extension_len);

        let len = size_of::<u16>() as u8;
        self.push(len);
        self.extend_from_slice(&ProtocolVersion::TlsOnePointThree.to_be_bytes());
    }

    fn supported_groups(&mut self) {
        let extension_name = (Extension::SupportedGroups as u16).to_be_bytes();
        self.extend_from_slice(&extension_name);

        let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
        self.extend_from_slice(&extension_len);

        let len = (size_of::<u16>() as u16).to_be_bytes();
        self.extend_from_slice(&len);

        let groups = NamedGroup::Secp256r1.to_be_bytes();
        self.extend_from_slice(&groups);
    }

    fn signature_algorithms(&mut self) {
        let extension_name = Extension::SignatureAlgorithms.to_be_bytes();
        self.extend_from_slice(&extension_name);

        let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
        self.extend_from_slice(&extension_len);

        let len = (size_of::<u16>() as u16).to_be_bytes();
        self.extend_from_slice(&len);

        let scheme = SignatureScheme::EcdsaSecp256r1Sha256.to_be_bytes();
        self.extend_from_slice(&scheme);
    }

    fn key_share(&mut self, group_keys: &GroupKeys) {
        let extension_name = Extension::KeyShare.to_be_bytes();
        self.extend_from_slice(&extension_name);

        let original_len = self.len();
        self.extend_from_slice(&[0; 2]);

        self.secp256r1_key_share(group_keys);

        let len_diff = ((self.len() - original_len) as u16).to_be_bytes();
        self[original_len..][..2].copy_from_slice(&len_diff);
    }

    fn secp256r1_key_share(&mut self, group_keys: &GroupKeys) {
        let named_group = NamedGroup::Secp256r1.to_be_bytes();
        self.extend_from_slice(&named_group);
        self.push(4);
        let pub_key = Secp256r1::BASE_POINT
            .as_projective()
            .mul_scalar(group_keys.secp256r1.inner())
            .as_affine()
            .expect("private key isn't 0");
        self.extend_from_slice(&pub_key.x().to_be_bytes());
        self.extend_from_slice(&pub_key.y().to_be_bytes());
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

        let cipher_suites_len = u16::from_be_bytes(client_hello[pos..][..2].try_into().unwrap());
        pos += 2;
        if cipher_suites_len > 0xfffe {
            return Err(CliHelloParseError::InvalidLengthEncoding);
        }

        let cipher_suites = &client_hello[pos..][..cipher_suites_len as usize];
        pos += cipher_suites_len as usize;

        let legacy_compression_methods_len = client_hello[pos];
        pos += 1;
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
