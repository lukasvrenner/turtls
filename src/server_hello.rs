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
    pub(crate) fn parse(
        record_layer: &'a mut RecordLayer,
    ) -> Result<Self, SerHelParseError> {
        record_layer.read(ContentType::Handshake)?;
        let handshake_msg = record_layer.buf();
        if handshake_msg.len() < SHAKE_HEADER_SIZE + ServerHello::MIN_LEN {
            record_layer.alert(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }
        if handshake_msg[0] != ShakeType::ServerHello.to_byte() {
            record_layer.alert(Alert::UnexpectedMessage);
            return Err(SerHelParseError::Failed);
        }
        let len =
            u32::from_be_bytes([0, handshake_msg[1], handshake_msg[2], handshake_msg[3]]) as usize;

        if len < handshake_msg.len() - SHAKE_HEADER_SIZE {
            record_layer.alert(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        if len > handshake_msg.len() - SHAKE_HEADER_SIZE {
            record_layer.alert(Alert::HandshakeFailure);
            return Err(SerHelParseError::Failed);
        }

        let server_hello = &handshake_msg[SHAKE_HEADER_SIZE..];

        if server_hello.len() < ServerHello::MIN_LEN {
            record_layer.alert(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        let mut pos = size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN;

        let leg_session_id_len = server_hello[pos];
        if leg_session_id_len > 32 {
            record_layer.alert(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }
        pos += size_of_val(&leg_session_id_len) + leg_session_id_len as usize;

        let cipher_suite = CipherList::parse_singular(
            server_hello[pos..][..size_of::<CipherSuite>()]
                .try_into()
                .unwrap(),
        );
        pos += size_of::<CipherSuite>();

        pos += size_of_val(&ServerHello::LEGACY_COMPRESSION_METHOD);

        let extensions_len =
            u16::from_be_bytes(server_hello[pos..][..2].try_into().unwrap()) as usize;

        pos += Extensions::LEN_SIZE;
        if extensions_len != server_hello.len() - pos {
            record_layer.alert(Alert::DecodeError);
            return Err(SerHelParseError::Failed);
        }

        let extensions = ExtensionsRef::parse(&server_hello[pos..]);

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
