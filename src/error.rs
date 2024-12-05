use crate::alert::Alert;
use crate::extensions::key_share::KeyGenError;
use crate::record::{IoError, ReadError};

#[derive(Debug)]
pub(crate) enum TlsError {
    /// The peer has sent an [`Alert`].
    Received(Alert),
    /// An error has occured that can be described as an [`Alert`].
    Sent(Alert),
}

/// The result of the handshake.
///
/// If a value other than `Ok` is returned, the connection is closed.
#[must_use]
#[repr(C)]
pub enum ShakeResult {
    /// Indicates a successful handshake.
    Ok,
    /// Indicates that the peer sent an alert.
    ReceivedAlert(Alert),
    /// Indicates that an alert was sent to the peer.
    SentAlert(Alert),
    /// Indicates that there was an error generating a random number.
    RngError,
    /// Indicates that there was an error performing an IO operation.
    IoError,
    /// Indicates that the record read took too long.
    Timeout,
    /// Indicates that the randomly-generated private key was zero.
    PrivKeyIsZero,
    MissingExtensions,
}

impl From<TlsError> for ShakeResult {
    fn from(value: TlsError) -> Self {
        match value {
            TlsError::Sent(err) => Self::SentAlert(err),
            TlsError::Received(err) => Self::ReceivedAlert(err),
        }
    }
}

impl From<ReadError> for ShakeResult {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::IoError => Self::IoError,
            ReadError::Timeout => Self::Timeout,
            ReadError::Alert(err) => err.into(),
        }
    }
}

impl From<IoError> for ShakeResult {
    fn from(value: IoError) -> Self {
        match value {
            IoError::IoError => Self::IoError,
            IoError::WantMore => Self::Timeout,
        }
    }
}

impl From<KeyGenError> for ShakeResult {
    fn from(value: KeyGenError) -> Self {
        match value {
            KeyGenError::RngError => Self::RngError,
            KeyGenError::PrivKeyIsZero => Self::PrivKeyIsZero,
            KeyGenError::NoGroups => Self::MissingExtensions,
        }
    }
}
