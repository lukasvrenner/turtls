use crate::handshake::{ShakeMsg, ShakeStatus, ShakeType};

use super::Message;
pub extern "C" fn handshake(
    read: extern "C" fn() -> Message,
    write: extern "C" fn(Message),
) -> ShakeStatus {
    todo!()
}

fn client_hello(write: extern "C" fn(Message), csprng: impl FnOnce() -> [u8; 32]) {
    // TODO make the length the proper length
    let mut msg = ShakeMsg::new(ShakeType::ClientHello, 41);

    let legacy_version = [0x03, 0x03];
    msg.extend_from_slice(&legacy_version);

    let random_bytes = csprng();
    msg.extend_from_slice(&random_bytes);

    let legacy_session_id = 0x00;
    msg.push(legacy_session_id);

    // TODO: allow this to be customizable
    let cipher_suite_len = 0x01;
    let aes128_gcm_sha256 = [0x13, 0x01];
    msg.push(cipher_suite_len);
    msg.extend_from_slice(&aes128_gcm_sha256);

    let legacy_compression_methods = 0x00;
    msg.push(legacy_compression_methods);

    let extension_len = 0x00;
    // TODO add extensions
    let extensions = [0x00];
    msg.push(extension_len);
    msg.extend_from_slice(&extensions);

    let send_msg = Message {
        ptr: &msg as &[u8] as *const [u8] as *const u8,
        len: msg.len(),
    };
    write(send_msg);
    todo!()
}
