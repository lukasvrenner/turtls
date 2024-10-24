use std::mem::MaybeUninit;

use crate::aead::{AeadWriter, AeadReader};
use crate::cipher_suites::GroupKeys;
use crate::record::{ContentType, Io, RecordLayer};

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,
    group_keys: GroupKeys,
    msg_buf: RecordLayer,
}

impl State {
    pub fn new_uninit() -> Box<MaybeUninit<Self>> {
        Box::new_uninit()
    }

    pub fn init_buf_with(state: &mut MaybeUninit<Self>, msg_type: ContentType, io: Io) -> &mut RecordLayer {
        let state_ptr = state.as_mut_ptr();
        // SAFETY: buf_ptr is a valid MaybeUninit<RecordLayer>
        let buf_ptr = unsafe { &mut *(&raw mut (*state_ptr).msg_buf as *mut MaybeUninit<RecordLayer>) };
        RecordLayer::init(buf_ptr, msg_type, io)
    }
}
