use crate::cipher_suites::CipherSuite;
use crate::LEGACY_PROTO_VERS;
pub fn server_hello(
    msg_buf: &mut [u8],
    csprng: impl FnOnce() -> [u8; 32],
    leg_session_id: &[u8],
    cipher_suite: CipherSuite,
    extensions: &[u8],
) {
    let mut pos = 0;

    msg_buf[pos..][..2].copy_from_slice(&LEGACY_PROTO_VERS);
    pos += 1;

    msg_buf[pos..][..32].copy_from_slice(&csprng());
    pos += 32;

    // legacy session id len
    msg_buf[pos] = leg_session_id.len() as u8;
    pos += 1;

    // legacy session id
    msg_buf[pos..][..leg_session_id.len()].copy_from_slice(&leg_session_id);
    pos += leg_session_id.len();

    // cipher suite
    let suite = (cipher_suite as u16).to_be_bytes();
    msg_buf[pos..][..2].copy_from_slice(&suite);
    pos += 2;

    // legacy compression method
    msg_buf[pos] = 0;
    pos += 1;

    assert!(
        extensions.len() >= 6,
        "at least three extensions must be used"
    );
    let extensions_len = (extensions.len() as u16).to_be_bytes();
    msg_buf[pos..][..2].copy_from_slice(&extensions_len);
    pos += 2;

    msg_buf[pos..][..extensions.len()].copy_from_slice(&extensions);
    assert_eq!(
        pos + extensions.len(),
        msg_buf.len(),
        "buf must exactly fit contents"
    );
}
