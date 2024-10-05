use crate::versions::LEGACY_PROTO_VERS;
use crate::aead::AeadWriter;

#[repr(u8)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

pub fn plaintext_record(msg_type: ContentType, msg_data: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(msg_type as u8);
    msg.extend_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());

    msg.extend_from_slice(&[0, 0]);
    msg_data(&mut msg);
    let len = ((msg.len() - 5) as u16).to_be_bytes();
    msg[3..5].copy_from_slice(&len);

    msg
}

pub fn encrypted_record(
    msg_type: ContentType,
    msg_data: impl FnOnce(&mut Vec<u8>),
    aead_state: &mut AeadWriter
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(ContentType::ApplicationData as u8);
    msg.extend_from_slice(&LEGACY_PROTO_VERS.as_be_bytes());

    msg.extend_from_slice(&[0, 0]);


    msg_data(&mut msg);
    msg.push(msg_type as u8);

    let split_msg = msg.split_at_mut(5);
    let tag = aead_state.encrypt_inline(split_msg.1, split_msg.0);
    msg.extend_from_slice(&tag);

    let len = ((msg.len() - 5) as u16).to_be_bytes();
    msg[3..5].copy_from_slice(&len);

    msg
}
