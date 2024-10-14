use crate::aead::AeadWriter;
use crate::Message;

#[repr(u8)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

pub fn plaintext_record(msg_type: ContentType, msg_data: impl FnOnce(&mut Message)) -> Message {
    let mut msg = Message::new(msg_type);
    msg_data(&mut msg);
    msg
}

pub fn encrypted_record(
    msg_type: ContentType,
    msg_data: impl FnOnce(&mut Message),
    aead_state: &mut AeadWriter,
) -> Message {
    let mut msg = Message::new(ContentType::ApplicationData);
    msg_data(&mut msg);
    msg.push(msg_type as u8);

    let split_msg = msg.split_at_mut(5);
    let tag = aead_state.encrypt_inline(split_msg.1, split_msg.0);
    msg.extend_from_slice(&tag);
    msg
}
