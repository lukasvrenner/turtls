use std::time::Duration;

use crate::alert::Alert;
use crate::cipher_suites::{CipherList, CipherSuite};
use crate::error::TlsError;
use crate::extensions::{Extensions, SerHelExtRef};
use crate::handshake::{self, ShakeType, SHAKE_HEADER_SIZE};
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
    pub(crate) extensions: SerHelExtRef<'a>,
}

impl<'a> RecvdSerHello<'a> {
    /// Recieve and parse a ServerHello message.
    ///
    /// Note: this function makes the assumption that the ServerHello will be exactly one record.
    /// If the server sends a ServerHello that is broken into multiple records, it will alert
    /// `HandshakeFailed` and return an error.
    pub(crate) fn read(
        rl: &'a mut RecordLayer,
    ) -> Result<Self, ReadError> {
        rl.read()?;
        if rl.msg_type() != ContentType::Handshake.to_byte() {
            return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
        }

        if rl.data_len() < SHAKE_HEADER_SIZE + ServerHello::MIN_LEN {
            return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
        }

        let handshake_msg = rl.data();

        if handshake_msg[0] != ShakeType::ServerHello.to_byte() {
            return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
        }

        let len = u32::from_be_bytes([
            0,
            handshake_msg[1],
            handshake_msg[2],
            handshake_msg[3],
        ]) as usize;

        // ServerHello must be the only message in the record
        if len < handshake_msg.len() - SHAKE_HEADER_SIZE {
            return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
        }

        // ServerHello must not be more than one record (implemntation detail)
        if len > handshake_msg.len() - SHAKE_HEADER_SIZE {
            return Err(ReadError::Alert(TlsError::Sent(Alert::HandshakeFailure)));
        }

        if len < ServerHello::MIN_LEN {
            return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
        }

        let ser_hel = &handshake_msg[SHAKE_HEADER_SIZE..];

        let mut pos =
            size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN;

        let leg_session_id_len = ser_hel[pos];

        if leg_session_id_len > 32 {
            return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
        }
        pos += size_of_val(&leg_session_id_len) + leg_session_id_len as usize;

        let cipher_suite = CipherList::parse_singular(
            ser_hel[pos..][..size_of::<CipherSuite>()]
                .try_into()
                .unwrap(),
        );
        pos += size_of::<CipherSuite>();

        pos += size_of_val(&ServerHello::LEGACY_COMPRESSION_METHOD);

        let extensions_len =
            u16::from_be_bytes(ser_hel[pos..][..2].try_into().unwrap()) as usize;

        pos += Extensions::LEN_SIZE;
        if extensions_len != ser_hel[pos..].len() {
            return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
        }

        let extensions = match SerHelExtRef::parse(&ser_hel[pos..]) {
            Ok(ext) => ext,
            Err(err) => return Err(ReadError::Alert(TlsError::Sent(err))),
        };

        Ok(Self {
            cipher_suite,
            extensions,
        })
    }
}
