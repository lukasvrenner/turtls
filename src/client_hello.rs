use crate::cipher_suites::CipherSuites;
use crate::extensions::Extensions;
use crate::handshake::ShakeType;
use crate::record::{ContentType, RecordLayer};
use crate::versions::ProtocolVersion;
use crate::versions::LEGACY_PROTO_VERS;
use getrandom::{getrandom, Error};

pub struct ClientHello<'a, 'b> {
    pub cipher_suites: &'b CipherSuites,
    pub extensions: &'a Extensions,
}

impl<'a, 'b> ClientHello<'a, 'b> {
    pub const RANDOM_BYTES_LEN: usize = 32;
    pub const LEGACY_SESSION_ID: u8 = 0;
    pub const LEGACY_COMPRESSION_METHODS: [u8; 2] = [1, 0];
    pub const fn len(&self) -> usize {
        size_of::<ProtocolVersion>()
            + Self::RANDOM_BYTES_LEN
            // TODO use size_of_val once it is const-stabilized
            + 1
            + self.cipher_suites.len()
            // TODO use size_of_val once it is const-stabilized
            + 2
            + self.extensions.len()
    }

    pub fn write(&self, record_layer: &mut RecordLayer) -> Result<(), CliHelError> {
        record_layer.start_as(ContentType::Handshake);
        record_layer.push(ShakeType::ClientHello.as_byte());

        let len = (self.len() as u32).to_be_bytes();
        record_layer.extend_from_slice(&len[1..]);

        record_layer.extend_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());

        let mut random_bytes = [0; Self::RANDOM_BYTES_LEN];
        getrandom(&mut random_bytes)?;
        record_layer.extend_from_slice(&random_bytes);

        record_layer.push(Self::LEGACY_SESSION_ID);

        self.cipher_suites.write(record_layer);

        record_layer.extend_from_slice(&Self::LEGACY_COMPRESSION_METHODS);

        self.extensions.write(record_layer);
        record_layer.finish_and_send();
        Ok(())
    }
}

pub enum CliHelError {
    RngError,
    IoError,
}

impl From<Error> for CliHelError {
    fn from(_: Error) -> Self {
        Self::RngError
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
