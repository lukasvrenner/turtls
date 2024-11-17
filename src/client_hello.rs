use crate::cipher_suites::CipherList;
use crate::dh::GroupKeys;
use crate::extensions::Extensions;
use crate::handshake::ShakeType;
use crate::record::{ContentType, RecordLayer};
use crate::versions::ProtocolVersion;
use crate::versions::LEGACY_PROTO_VERS;
use getrandom::{getrandom, Error};

pub(crate) struct ClientHello {
    pub(crate) cipher_suites: CipherList,
    pub(crate) extensions: Extensions,
}

impl ClientHello {
    pub(crate) const RANDOM_BYTES_LEN: usize = 32;
    pub(crate) const LEGACY_SESSION_ID: u8 = 0;
    pub(crate) const LEGACY_COMPRESSION_METHODS: [u8; 2] = [1, 0];
    pub(crate) fn len(&self) -> usize {
        size_of::<ProtocolVersion>()
            + Self::RANDOM_BYTES_LEN
            // TODO use size_of_val once it is const-stabilized
            + size_of_val(&Self::LEGACY_SESSION_ID)
            + CipherList::LEN_SIZE
            + self.cipher_suites.len()
            // TODO use size_of_val once it is const-stabilized
            + size_of_val(&Self::LEGACY_COMPRESSION_METHODS)
            + Extensions::LEN_SIZE
            + self.extensions.len_client()
    }

    pub(crate) fn write_to(
        &self,
        record_layer: &mut RecordLayer,
        keys: &GroupKeys,
    ) -> Result<(), CliHelError> {
        record_layer.start_as(ContentType::Handshake);
        record_layer.push(ShakeType::ClientHello.to_byte());

        let len = self.len() as u32;
        record_layer.push_u24(len);

        record_layer.push_u16(LEGACY_PROTO_VERS.as_int());

        let mut random_bytes = [0; Self::RANDOM_BYTES_LEN];
        getrandom(&mut random_bytes)?;
        record_layer.extend_from_slice(&random_bytes);

        record_layer.push(Self::LEGACY_SESSION_ID);

        let len = self.cipher_suites.len() as u16;
        record_layer.push_u16(len);
        self.cipher_suites.write_to(record_layer);

        record_layer.extend_from_slice(&Self::LEGACY_COMPRESSION_METHODS);

        let len = self.extensions.len_client() as u16;
        record_layer.push_u16(len);
        self.extensions.write_client(record_layer, keys);

        record_layer.finish_and_send();
        Ok(())
    }
}

pub(crate) enum CliHelError {
    RngError,
    IoError,
}

impl From<Error> for CliHelError {
    fn from(_: Error) -> Self {
        Self::RngError
    }
}

pub(crate) enum CliHelloParseError {
    MissingData,
    InvalidLengthEncoding,
}

pub(crate) struct ClientHelloRef<'a> {
    pub(crate) random_bytes: &'a [u8; 32],
    pub(crate) session_id: &'a [u8],
    pub(crate) cipher_suites: &'a [u8],
    pub(crate) extensions: &'a [u8],
}

impl<'a> ClientHelloRef<'a> {
    pub(crate) fn parse(client_hello: &'a [u8]) -> Result<Self, CliHelloParseError> {
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
