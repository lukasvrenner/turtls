use crate::record::RecordLayer;

/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection(pub(crate) Option<RecordLayer>);
