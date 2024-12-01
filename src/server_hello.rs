use crate::alert::Alert;
use crate::cipher_suites::{CipherList, CipherSuite};
use crate::error::TlsError;
use crate::extensions::versions::ProtocolVersion;
use crate::extensions::{self, ExtList};
use crate::handshake::{ShakeType, SHAKE_HEADER_SIZE};
use crate::record::{ContentType, ReadError};
use crate::state::ShakeState;

pub(crate) struct ServerHello<'a> {
    leg_sesion_id: &'a [u8],
    cipher_suite: CipherList,
    extensions: ExtList,
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
        + ExtList::LEN_SIZE;
}

pub(crate) fn read_and_parse(
    state: &mut ShakeState,
) -> Result<(), ReadError> {
    state.read()?;
    if state.rl_state.rl.msg_type() != ContentType::Handshake.to_byte() {
        return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
    }

    if state.msg_buf.msg_len() < SHAKE_HEADER_SIZE + ServerHello::MIN_LEN {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }

    if state.msg_buf.buf()[0] != ShakeType::ServerHello.to_byte() {
        return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
    }

    let len =
        u32::from_be_bytes([0, state.msg_buf.buf()[1], state.msg_buf.buf()[2], state.msg_buf.buf()[3]]) as usize;

    // ServerHello must be the only message in the record
    if len < state.msg_buf.msg_len() - SHAKE_HEADER_SIZE {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }

    // ServerHello must not be more than one record (implemntation detail)
    if len > state.msg_buf.msg_len() - SHAKE_HEADER_SIZE {
        return Err(ReadError::Alert(TlsError::Sent(Alert::HandshakeFailure)));
    }

    if len < ServerHello::MIN_LEN {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }

    state.msg_buf.advance(SHAKE_HEADER_SIZE);

    state.msg_buf.advance(size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN);

    let leg_session_id_len = state.msg_buf.buf()[0];

    if leg_session_id_len > 32 {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }
    state.msg_buf.advance(size_of_val(&leg_session_id_len) + leg_session_id_len as usize);

    state.rl_state.ciphers.suites &= CipherList::parse_singular(
        state.msg_buf.buf()[..size_of::<CipherSuite>()]
            .try_into()
            .unwrap(),
    )
    .suites;
    state.msg_buf.advance(size_of::<CipherSuite>());

    state.msg_buf.advance(size_of_val(&ServerHello::LEGACY_COMPRESSION_METHOD));

    let extensions_len = u16::from_be_bytes(state.msg_buf.buf()[..2].try_into().unwrap()) as usize;

    state.msg_buf.advance(ExtList::LEN_SIZE);
    if extensions_len != state.msg_buf.buf().len() {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }
    if let Err(alert) = extensions::parse_ser_hel_exts(state) {
        return Err(ReadError::Alert(TlsError::Sent(alert)));
    }
    Ok(())
}
