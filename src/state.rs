use std::mem::MaybeUninit;

use crate::record::{EncryptedRecLayer, Io,};

/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub(crate) enum Connection {
    Uninit,
    Init(State),
}

pub(crate) struct State {
    pub(crate) rl: EncryptedRecLayer,
}

impl State {
    pub(crate) fn new(io: Io) -> Self {
        Self {
            rl: EncryptedRecLayer::new(io)
        }
    }
}
