use crylib::hash::Sha256;

use crate::alert::Alert;
use crate::cipher_suites::{CipherList, CipherSuite};
use crate::config::Config;
use crate::error::TlsError;
use crate::extensions::versions::ProtocolVersion;
use crate::extensions::{self, ExtList};
use crate::handshake::ShakeType;
use crate::record::{ReadError, RecordLayer};
use crate::state::{ShakeState, State};

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

pub(crate) fn server_hello_client(shake_state: &mut ShakeState, state: &mut State) -> Result<(), ReadError> {
    assert!(shake_state.next == ShakeType::ServerHello);
    shake_state.buf.read(&mut state.rl)?;

    if shake_state.buf.msg_type() != ShakeType::ServerHello.to_byte() {
        return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
    }

    if shake_state.buf.len() < ServerHello::MIN_LEN {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }

    let mut pos = size_of::<ProtocolVersion>() + ServerHello::RANDOM_BYTES_LEN;

    let leg_session_id_len = shake_state.buf.data()[pos];

    if leg_session_id_len > 32 {
        return Err(ReadError::Alert(TlsError::Sent(Alert::DecodeError)));
    }
    pos += size_of_val(&leg_session_id_len) + leg_session_id_len as usize;

    shake_state.crypto.ciphers.suites &= CipherList::parse_singular(
        shake_state.buf.data()[pos..][..size_of::<CipherSuite>()]
            .try_into()
            .unwrap(),
    )
    .suites;
    pos += size_of::<CipherSuite>();

    pos += size_of_val(&ServerHello::LEGACY_COMPRESSION_METHOD);

    if let Err(alert) =
        extensions::parse_ser_hel_exts(&shake_state.buf.data()[pos..], &mut shake_state.crypto, state)
    {
        return Err(ReadError::Alert(TlsError::Sent(alert)));
    }
    shake_state.next = ShakeType::EncryptedExtensions;
    Ok(())
}
