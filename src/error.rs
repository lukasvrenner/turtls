use crate::alert::Alert;
use crate::extensions::key_share::KeyGenError;
use crate::record::ReadError;

/// The result of the handshake.
///
/// If a value other than `Ok` is returned, the connection is closed.
#[must_use]
#[repr(C)]
pub enum Error {
    /// There were no errors
    None,
    /// The peer sent an alert.
    ReceivedAlert(Alert),
    /// An alert was sent to the peer.
    SentAlert(Alert),
    /// There was an error generating a random number.
    RngError,
    /// A read operation failed.
    ///
    /// This error IS resumable if the error is recoverable
    WantRead,
    /// A write operation failed.
    ///
    /// This error IS resumable if the error is recoverable
    WantWrite,
    /// The randomly-generated private key was zero.
    PrivKeyIsZero,
    /// One or more required extensions are missing.
    MissingExtensions,
}

impl From<ReadError> for Error {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::IoError => Self::WantRead,
            ReadError::Alert(alert) => Self::SentAlert(alert),
        }
    }
}

impl From<KeyGenError> for Error {
    fn from(value: KeyGenError) -> Self {
        match value {
            KeyGenError::RngError => Self::RngError,
            KeyGenError::PrivKeyIsZero => Self::PrivKeyIsZero,
            KeyGenError::NoGroups => Self::MissingExtensions,
        }
    }
}
