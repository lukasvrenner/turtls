use crate::alert::Alert;
use crate::cipher_suites::{CipherList, CipherSuite};
use crate::error::TlsError;
use crate::extensions::versions::ProtocolVersion;
use crate::extensions::{self, ExtList};
use crate::handshake::ShakeType;
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

    if state.msg_buf.msg_type() != ShakeType::ServerHello.to_byte() {
        return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
    }

    if state.msg_buf.len() < ServerHello::MIN_LEN {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }


    let mut pos = size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN;

    let leg_session_id_len = state.msg_buf.data()[pos];

    if leg_session_id_len > 32 {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }
    pos += size_of_val(&leg_session_id_len) + leg_session_id_len as usize;

    state.rl_state.ciphers.suites &= CipherList::parse_singular(
        state.msg_buf.data()[pos..][..size_of::<CipherSuite>()]
            .try_into()
            .unwrap(),
    )
    .suites;
    pos += size_of::<CipherSuite>();

    pos += size_of_val(&ServerHello::LEGACY_COMPRESSION_METHOD);

    let extensions_len = u16::from_be_bytes(state.msg_buf.data()[pos..][..2].try_into().unwrap()) as usize;

    pos += ExtList::LEN_SIZE;
    if extensions_len != state.msg_buf.data().len() - pos {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }
    if let Err(alert) = extensions::parse_ser_hel_exts(&state.msg_buf.data()[pos..], &mut state.rl_state) {
        return Err(ReadError::Alert(TlsError::Sent(alert)));
    }
    Ok(())
}
