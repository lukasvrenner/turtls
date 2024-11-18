use std::mem::MaybeUninit;

use crate::aead::TlsAead;
use crate::init::TagUninit;
use crate::record::{ContentType, Io, RecordLayer};

/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection(pub(crate) TagUninit<State>);

pub(crate) struct State {
    pub(crate) aead_writer: TlsAead,
    pub(crate) aead_reader: TlsAead,
    pub(crate) record_layer: RecordLayer,
}

impl State {
    pub(crate) fn init_record_layer(
        state: &mut MaybeUninit<Self>,
        msg_type: ContentType,
        io: Io,
    ) -> &mut RecordLayer {
        let state_ptr = state.as_mut_ptr();
        // SAFETY: `MaybeUninit<T>` has the same memory layout as `T` so we can
        // access pointers to fields as long as we cast the pointer back into a `MaybeUninit`.
        let buf_ptr =
            unsafe { &raw mut (*state_ptr).record_layer as *mut MaybeUninit<RecordLayer> };
        // SAFETY: The pointer was just grabbed from a valid field.
        let buf_ref = unsafe { &mut *buf_ptr };
        RecordLayer::init(buf_ref, msg_type, io)
    }
}
