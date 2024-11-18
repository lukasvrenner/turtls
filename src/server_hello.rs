use std::time::Duration;

use crate::alert::Alert;
use crate::cipher_suites::{CipherList, CipherSuite};
use crate::error::TlsError;
use crate::extensions::{ExtParseError, Extensions, SerHelExtPeer};
use crate::handshake::{ShakeType, SHAKE_HEADER_SIZE};
use crate::record::{ContentType, ReadError, RecordLayer};
use crate::versions::ProtocolVersion;

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
    pub(crate) cipher_suite: CipherList,
    pub(crate) extensions: SerHelExtPeer<'a>,
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
    ) -> Result<Self, ReadError> {
        record_layer.read(ContentType::Handshake, record_timeout)?;

        if record_layer.len() < SHAKE_HEADER_SIZE + ServerHello::MIN_LEN {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::DecodeError)));
        }

        if record_layer.buf()[0] != ShakeType::ServerHello.to_byte() {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::UnexpectedMessage)));
        }

        let len = u32::from_be_bytes([
            0,
            record_layer.buf()[1],
            record_layer.buf()[2],
            record_layer.buf()[3],
        ]) as usize;

        // ServerHello must be the only message in the record
        if len < record_layer.len() - SHAKE_HEADER_SIZE {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::DecodeError)));
        }

        // ServerHello must not be more than one record (implemntation detail)
        if len > record_layer.len() - SHAKE_HEADER_SIZE {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::HandshakeFailure)));
        }

        if record_layer.len() - SHAKE_HEADER_SIZE < ServerHello::MIN_LEN {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::DecodeError)));
        }

        let mut pos =
            size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN + SHAKE_HEADER_SIZE;

        let leg_session_id_len = record_layer.buf()[pos];

        if leg_session_id_len > 32 {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::DecodeError)));
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
            return Err(ReadError::TlsError(TlsError::Alert(Alert::DecodeError)));
        }

        let extensions = match SerHelExtPeer::parse(&record_layer.buf()[pos..]) {
            Ok(ext) => ext,
            Err(ExtParseError::InvalidExt) => {
                return Err(ReadError::TlsError(TlsError::Alert(Alert::UnsupportedExtension)));
            },
            Err(ExtParseError::ParseError) => {
                return Err(ReadError::TlsError(TlsError::Alert(Alert::DecodeError)));
            },
            Err(ExtParseError::MissingExt) => {
                return Err(ReadError::TlsError(TlsError::Alert(Alert::MissingExtension)));
            },
        };

        Ok(Self {
            cipher_suite,
            extensions,
        })
    }
}
