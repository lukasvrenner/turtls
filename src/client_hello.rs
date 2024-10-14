use crate::cipher_suites::CipherSuite;
use crate::versions::LEGACY_PROTO_VERS;
use crate::{extensions, Message};

pub fn client_hello(msg_buf: &mut Message) {
    legacy_protocol_version(msg_buf);

    random_bits(msg_buf);

    legacy_session_id(msg_buf);

    cipher_suites(msg_buf);

    legacy_compression_methods(msg_buf);

    extensions(msg_buf);
}

fn legacy_protocol_version(msg_buf: &mut Message) {
    msg_buf.extend_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
}

fn random_bits(msg_buf: &mut Message) {
    todo!()
}

fn legacy_session_id(msg_buf: &mut Message) {
    msg_buf.push(0x00);
}

fn cipher_suites(msg_buf: &mut Message) {
    let len = 1u16.to_be_bytes();
    msg_buf.extend_from_slice(&len);
    let aes128_gcm_sha256 = CipherSuite::Aes128GcmSha256.as_be_bytes();
    msg_buf.extend_from_slice(&aes128_gcm_sha256);
}

fn legacy_compression_methods(msg_buf: &mut Message) {
    msg_buf.push(0x00);
}

fn extensions(msg_buf: &mut Message) {
    msg_buf.extend_from_slice(&[0, 0]);
    let original_len = msg_buf.data_len();

    extensions::supported_groups(msg_buf);
    extensions::signature_algorithms(msg_buf);
    extensions::supported_versions_client(msg_buf);

    let extensions_len = ((original_len - msg_buf.data_len()) as u16).to_be_bytes();
    msg_buf[original_len as usize - 2..][..2].copy_from_slice(&extensions_len);
    todo!()
}
