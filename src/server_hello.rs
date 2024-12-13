use crate::aead::TlsAead;
use crate::cipher_suites::{CipherSuite, TurtlsCipherList};
use crate::client_hello::RANDOM_BYTES_LEN;
use crate::extensions::versions::ProtocolVersion;
use crate::extensions::{self, TurtlsExts};
use crate::state::{GlobalState, UnprotShakeState};
use crate::TurtlsAlert;

pub(crate) const MIN_LEN: usize = size_of::<ProtocolVersion>()
    + RANDOM_BYTES_LEN
    + 3
    + size_of::<CipherSuite>()
    + 1
    + TurtlsExts::LEN_SIZE;

pub(crate) fn server_hello_client(
    ser_hel: &[u8],
    unprot_state: &mut UnprotShakeState,
    global_state: &mut GlobalState,
) -> Result<TlsAead, TurtlsAlert> {
    if ser_hel.len() < MIN_LEN {
        return Err(TurtlsAlert::DecodeError);
    }

    let mut pos = size_of::<ProtocolVersion>() + RANDOM_BYTES_LEN;

    let leg_session_id_len = ser_hel[pos];

    if leg_session_id_len > 32 {
        return Err(TurtlsAlert::DecodeError);
    }
    pos += size_of_val(&leg_session_id_len) + leg_session_id_len as usize;

    unprot_state.ciphers.suites &= TurtlsCipherList::parse_singular(
        ser_hel[pos..][..size_of::<CipherSuite>()]
            .try_into()
            .unwrap(),
    )
    .suites;
    pos += size_of::<CipherSuite>();

    pos += 1;

    extensions::parse_ser_hel_exts(&ser_hel[pos..], unprot_state, global_state)
}
