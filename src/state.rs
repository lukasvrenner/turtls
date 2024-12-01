use crylib::hash::Sha256;

use crate::extensions::key_share::GroupKeys;
use crate::handshake::MsgBuf;
use crate::record::{ReadError, RecordLayer};
use crate::CipherList;
/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection {
    pub(crate) rl: Option<RecordLayer>,
    pub(crate) app_proto: [u8; 256],
}

impl Connection {
    pub(crate) fn new() -> Box<Self> {
        Box::new(Self {
            rl: None,
            app_proto: [0; 256],
        })
    }
}

pub(crate) struct ShakeState<'a> {
    pub(crate) rl_state: RlState<'a>,
    pub(crate) msg_buf: MsgBuf,
}

impl<'a> ShakeState<'a> {
    pub(crate) fn read(&mut self) -> Result<(), ReadError> {
        self.msg_buf.read(&mut self.rl_state.rl)
    }
}

pub(crate) struct RlState<'a> {
    pub(crate) priv_keys: GroupKeys,
    pub(crate) secret: [u8; Sha256::HASH_SIZE],
    pub(crate) rl: &'a mut RecordLayer,
    pub(crate) ciphers: CipherList,
    pub(crate) sup_groups: u16,
    pub(crate) sig_algs: u16,
}
