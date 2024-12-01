use crate::record::RecordLayer;
/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection {
    pub(crate) rl: Option<RecordLayer>,
    pub(crate) app_proto: [u8; 256],
}

impl Connection {
    pub(crate) fn new() -> Self {
        Self {
            rl: None,
            app_proto: [0; 256],
        }
    }
}
