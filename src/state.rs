use std::mem::MaybeUninit;
use std::sync::RwLock;
use std::time::Duration;

use crate::aead::{AeadReader, AeadWriter};
use crate::cipher_suites::GroupKeys;
use crate::record::{ContentType, Io, RecordLayer};

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,
    group_keys: GroupKeys,
    msg_buf: RecordLayer,
    config: Config
}

pub struct Config {
    read_timeout: Duration,
}

impl State {
    pub fn new_uninit() -> Box<MaybeUninit<Self>> {
        Box::new_uninit()
    }

    pub fn init_buf_with(
        state: &mut MaybeUninit<Self>,
        msg_type: ContentType,
        io: Io,
    ) -> &mut RecordLayer {
        let state_ptr = state.as_mut_ptr();
        // SAFETY: a MaybeUninit<State> has a valid MaybeUninit<RecordLayer>
        let buf_ptr =
            unsafe { &mut *(&raw mut (*state_ptr).msg_buf as *mut MaybeUninit<RecordLayer>) };
        RecordLayer::init(buf_ptr, msg_type, io)
    }

    pub fn get_uninit_config(state: &mut MaybeUninit<Self>) -> &mut MaybeUninit<Config> {
        // SAFETY: a MaybeUninit<State> has a valid MaybeUninit<Config>
        unsafe {
            let config_ptr = &raw mut (*state.as_mut_ptr()).config.read_timeout;
            &mut *(config_ptr as *mut MaybeUninit<Config>)
        }
    }
}
