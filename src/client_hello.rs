use crate::cipher_suites::CipherSuite;
use crate::extensions;
use crate::handshake::Handshake;
use crate::record::Message;
use crate::versions::LEGACY_PROTO_VERS;
use getrandom::getrandom;
use getrandom::Error;

pub struct ClientHello {
    handshake: Handshake,
}

impl ClientHello {
    pub fn new(handshake: Handshake) -> Self {
        Self { handshake }
    }

    pub fn legacy_protocol_version(&mut self) {
        self.extend_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());
    }

    pub fn random_bits(&mut self) -> Result<(), Error> {
        self.extend_from_slice(&[0; 32]);
        let len = self.len();
        getrandom(&mut self[len - 32..])
    }

    pub fn legacy_session_id(&mut self) {
        self.push(0x00);
    }
}

impl std::ops::Deref for ClientHello {
    type Target = Handshake;
    fn deref(&self) -> &Self::Target {
        &self.handshake
    }
}

impl std::ops::DerefMut for ClientHello {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handshake
    }
}

//pub fn client_hello(msg_buf: &mut Message) -> Result<(), Error> {
//    let original_len = msg_buf.len();
//    msg_buf.push(ShakeType::ClientHello as u8);
//    msg_buf.extend_from_slice(&[0; 2]);
//    legacy_protocol_version(msg_buf);
//
//    random_bits(msg_buf)?;
//
//    legacy_session_id(msg_buf);
//
//    cipher_suites(msg_buf);
//
//    legacy_compression_methods(msg_buf);
//
//    extensions(msg_buf);
//
//    let len_diff = ((msg_buf.len() - original_len) as u16).to_be_bytes();
//    msg_buf[original_len..][..2].copy_from_slice(&len_diff);
//    Ok(())
//}

fn random_bits(msg_buf: &mut Message) -> Result<(), Error> {
    let len = msg_buf.len();
    msg_buf.extend_from_slice(&[0; 32]);
    getrandom(&mut msg_buf[len..][..2])
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
    let original_len = msg_buf.len();

    extensions::supported_groups(msg_buf);
    extensions::signature_algorithms(msg_buf);
    extensions::supported_versions_client(msg_buf);

    let extensions_len = ((original_len - msg_buf.len()) as u16).to_be_bytes();
    msg_buf[original_len - 2..][..2].copy_from_slice(&extensions_len);
}
