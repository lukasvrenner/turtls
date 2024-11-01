use std::mem::MaybeUninit;
use std::time::Duration;

use crate::aead::{AeadReader, AeadWriter};
use crate::cipher_suites::GroupKeys;
use crate::record::{ContentType, Io, RecordLayer};

pub struct State {
    aead_writer: AeadWriter,
    aead_reader: AeadReader,
    msg_buf: RecordLayer,
    config: Config,
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
        // SAFETY: `MaybeUninit<T>` has the same memory layout as `T` so we can
        // access pointers to fields as long as we cast the pointer back into a `MaybeUninit`.
        let buf_ptr = unsafe { &raw mut (*state_ptr).msg_buf as *mut MaybeUninit<RecordLayer> };
        // SAFETY: The pointer was just grabbed from a valid field.
        let buf_ref = unsafe { &mut *buf_ptr };
        RecordLayer::init(buf_ref, msg_type, io)
    }

    pub fn get_uninit_config(state: &mut MaybeUninit<Self>) -> &mut MaybeUninit<Config> {
        let state_ptr = state.as_mut_ptr();
        // SAFETY: `MaybeUninit<T>` has the same memory layout as `T` so we can
        // access pointers to fields as long as we cast the pointer back into a `MaybeUninit`.
        let config_ptr =
            unsafe { &raw mut (*state_ptr).config.read_timeout as *mut MaybeUninit<Config> };
        // SAFETY: The pointer was just grabbed from a valid field.
        unsafe { &mut *config_ptr }
    }
}
