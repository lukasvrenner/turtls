use std::time::Duration;

use crate::{
    cipher_suites::CipherSuite,
    extensions::{Extensions, ExtensionsRef},
    handshake::{ShakeType, SHAKE_HEADER_SIZE},
    record::{ContentType, ReadError, RecordLayer},
    versions::ProtocolVersion,
    Alert, CipherList, Config,
};
pub(crate) struct ServerHello<'a> {
    leg_sesion_id: &'a [u8],
    cipher_suite: CipherList,
    extensions: Extensions,
}

impl<'a> ServerHello<'a> {
    pub(crate) const RANDOM_BYTES_LEN: usize = 32;
    pub(crate) const LEG_SESS_ID_LEN_SIZE: usize = 1;
    pub(crate) const LEGACY_COMPRESSION_METHOD: u8 = 0;
    pub(crate) const MIN_LEN: usize = size_of::<ProtocolVersion>()
        + Self::RANDOM_BYTES_LEN
        + Self::LEG_SESS_ID_LEN_SIZE
        + size_of::<CipherSuite>()
        + 1
        + Extensions::LEN_SIZE;
}

pub struct RecvdSerHello<'a> {
    cipher_suite: CipherList,
    extensions: ExtensionsRef<'a>,
}

impl<'a> RecvdSerHello<'a> {
    /// Recieve and parse a ServerHello message.
    ///
    /// Note: this function makes the assumption that the ServerHello will be exactly one record.
    /// If the server sends a ServerHello that is broken into multiple records, it will alert
    /// `HandshakeFailed` and return an error.
    pub(crate) fn read(
        record_layer: &'a mut RecordLayer,
        record_timeout: Duration,
    ) -> Result<Self, SerHelParseError> {
        record_layer.read(ContentType::Handshake, record_timeout)?;

        if record_layer.len() < SHAKE_HEADER_SIZE + ServerHello::MIN_LEN {
            record_layer.alert_and_close(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        if record_layer.buf()[0] != ShakeType::ServerHello.to_byte() {
            record_layer.alert_and_close(Alert::UnexpectedMessage);
            return Err(SerHelParseError::Failed);
        }

        let buf = record_layer.buf();

        let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;

        // ServerHello must be the only message in the record
        if len < record_layer.len() - SHAKE_HEADER_SIZE {
            record_layer.alert_and_close(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        // ServerHello must not be more than one record (implemntation detail)
        if len > record_layer.len() - SHAKE_HEADER_SIZE {
            record_layer.alert_and_close(Alert::HandshakeFailure);
            return Err(SerHelParseError::Failed);
        }

        if record_layer.len() - SHAKE_HEADER_SIZE < ServerHello::MIN_LEN {
            record_layer.alert_and_close(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        let mut pos =
            size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN + SHAKE_HEADER_SIZE;

        let leg_session_id_len = record_layer.buf()[pos];
        if leg_session_id_len > 32 {
            record_layer.alert_and_close(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }
        pos += size_of_val(&leg_session_id_len) + leg_session_id_len as usize;

        let cipher_suite = CipherList::parse_singular(
            record_layer.buf()[pos..][..size_of::<CipherSuite>()]
                .try_into()
                .unwrap(),
        );
        pos += size_of::<CipherSuite>();

        pos += size_of_val(&ServerHello::LEGACY_COMPRESSION_METHOD);

        let extensions_len =
            u16::from_be_bytes(record_layer.buf()[pos..][..2].try_into().unwrap()) as usize;

        pos += Extensions::LEN_SIZE;
        if extensions_len != record_layer.buf()[pos..].len() {
            record_layer.alert_and_close(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        let extensions = ExtensionsRef::parse(&record_layer.buf()[pos..]);

        Ok(Self {
            cipher_suite,
            extensions,
        })
    }
}

pub(crate) enum SerHelParseError {
    ReadError(ReadError),
    Failed,
}

impl From<ReadError> for SerHelParseError {
    fn from(value: ReadError) -> Self {
        Self::ReadError(value)
    }
}
