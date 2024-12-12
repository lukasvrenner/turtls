use crate::cipher_suites::CipherList;
use crate::config::Config;
use crate::extensions::versions::{ProtocolVersion, LEGACY_PROTO_VERS};
use crate::extensions::ExtList;
use crate::handshake::{ShakeBuf, ShakeType};
use crate::state::UnprotShakeState;
use crate::Error;
use getrandom::getrandom;

pub(crate) const RANDOM_BYTES_LEN: usize = 32;
pub(crate) const LEGACY_SESSION_ID: u8 = 0;
pub(crate) const LEGACY_COMPRESSION_METHODS: [u8; 2] = [1, 0];

pub(crate) fn client_hello_client(
    unprot_state: &mut UnprotShakeState,
    shake_buf: &mut ShakeBuf,
    config: &Config,
) -> Error {
    shake_buf.start(ShakeType::ClientHello);

    shake_buf.extend_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());

    let mut random_bytes = [0; RANDOM_BYTES_LEN];
    if let Err(_) = getrandom(&mut random_bytes) {
        return Error::RngError;
    }
    shake_buf.extend_from_slice(&random_bytes);

    shake_buf.push(LEGACY_SESSION_ID);

    let len = (config.cipher_suites.len() as u16).to_be_bytes();
    shake_buf.extend_from_slice(&len);

    config.cipher_suites.write_to(shake_buf);

    shake_buf.extend_from_slice(&LEGACY_COMPRESSION_METHODS);

    let len = (config.extensions.len_client() as u16).to_be_bytes();
    shake_buf.extend_from_slice(&len);
    config
        .extensions
        .write_client(shake_buf, &unprot_state.priv_keys);
    Error::None
}
