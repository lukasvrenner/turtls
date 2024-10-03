use crate::extensions::ExtType;
use crate::handshake::{ShakeStatus, ShakeType};
use crate::LEGACY_PROTO_VERS;

pub extern "C" fn handshake(
    read: extern "C" fn(buf: *mut u8, len: usize),
    write: extern "C" fn(msg: *const u8, len: usize),
) -> ShakeStatus {
    todo!()
}

fn client_hello(
    msg_buf: &mut [u8],
    csprng: impl FnOnce() -> [u8; 32],
    cipher_suites: &[u8],
    extensions: &[u8],
) {
    // legacy protocol version
    let mut pos = 0;
    msg_buf[pos..][..2].copy_from_slice(&LEGACY_PROTO_VERS);
    pos += size_of_val(&LEGACY_PROTO_VERS);

    // random bytes
    msg_buf[pos..][..32].copy_from_slice(&csprng());
    pos += 32;

    // legacy session id
    msg_buf[pos] = 0x00;
    pos += 1;

    // cipher suites len
    assert!(cipher_suites.len() >= 2);
    let suites_len = (cipher_suites.len() as u16).to_be_bytes();
    msg_buf[pos..][..2].copy_from_slice(&suites_len);
    pos += size_of::<u16>();

    // cipher suites
    msg_buf[pos..][..cipher_suites.len()].copy_from_slice(cipher_suites);
    pos += cipher_suites.len();

    // legacy compression methods
    msg_buf[pos] = 0x00;
    pos += 1;

    // extensions len
    assert!(extensions.len() >= 8);
    let extensions_len = (extensions.len() as u16).to_be_bytes();
    msg_buf[pos..][..extensions.len()].copy_from_slice(&extensions_len);
    pos += extensions.len();

    msg_buf[pos..][..extensions.len()].copy_from_slice(extensions);
    assert_eq!(msg_buf.len(), pos + extensions.len());
}
