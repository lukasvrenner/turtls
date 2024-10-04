use crate::{extensions, LEGACY_PROTO_VERS};
use crate::cipher_suites::CipherSuite;

pub fn client_hello(
    msg_buf: &mut Vec<u8>,
    csprng: impl FnOnce() -> [u8; 32],
) {
    legacy_protocol_version(msg_buf);

    msg_buf.extend_from_slice(&csprng());

    legacy_session_id(msg_buf);

    cipher_suites(msg_buf);

    legacy_compression_methods(msg_buf);

    extensions(msg_buf);
}

fn legacy_protocol_version(msg_buf: &mut Vec<u8>) {
    msg_buf.extend_from_slice(&LEGACY_PROTO_VERS);
}

fn legacy_session_id(msg_buf: &mut Vec<u8>) {
    msg_buf.push(0x00);
}

fn cipher_suites(msg_buf: &mut Vec<u8>) {
    let len = 1u16.to_be_bytes();
    msg_buf.extend_from_slice(&len);
    let aes128_gcm_sha256 = (CipherSuite::Aes128GcmSha256 as u16).to_be_bytes();
    msg_buf.extend_from_slice(&aes128_gcm_sha256);
}

fn legacy_compression_methods(msg_buf: &mut Vec<u8>) {
    msg_buf.push(0x00);
}

fn extensions(msg_buf: &mut Vec<u8>) {
    todo!()
}
