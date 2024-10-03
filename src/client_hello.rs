use crate::LEGACY_PROTO_VERS;

pub fn client_hello(
    msg_buf: &mut Vec<u8>,
    csprng: impl FnOnce() -> [u8; 32],
    // TODO: can a &[CipherSuite] be used somehow?
    cipher_suites: &[u8],
    // TODO: can a &[Extension] be used somehow?
    extensions: &[u8],
) {
    // legacy protocol version
    msg_buf.extend_from_slice(&LEGACY_PROTO_VERS);

    // random bytes
    msg_buf.extend_from_slice(&csprng());

    // legacy session id
    msg_buf.push(0x00);

    // cipher suites len
    assert!(cipher_suites.len() >= 2, "at least one cipher suite must be used");
    let suites_len = (cipher_suites.len() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&suites_len);

    // cipher suites
    msg_buf.extend_from_slice(cipher_suites);

    // legacy compression methods
    msg_buf.push(0x00);

    // extensions len
    assert!(extensions.len() >= 8, "at least four extensions must be used");
    let extensions_len = (extensions.len() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extensions_len);

    msg_buf.extend_from_slice(extensions);
}
