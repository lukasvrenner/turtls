use crate::alert::Alert;
use crate::config::ConfigError;
use crate::client_hello::CliHelError;
use crate::record::ReadError;
use crate::dh::KeyGenError;

#[derive(Debug)]
pub(crate) enum TlsError {
    /// The peer has sent an [`Alert`].
    ReceivedAlert(Alert),
    /// An error has occured that can be described as an [`Alert`].
    Alert(Alert),
}

/// The result of the handshake.
// TODO: make this more explicit (have a type for each kind of failure).
#[must_use]
#[repr(C)]
pub enum ShakeResult {
    /// Indicates a successful handshake.
    Ok,
    /// Indicates that the peer sent an alert.
    ReceivedAlert(Alert),
    PeerError(Alert),
    /// Indicates that there was an error generating a random number.
    RngError,
    /// Indicates that there was an error performing an IO operation.
    IoError,
    Timeout,
    /// Indicates that the randomly-generated private key was zero.
    PrivKeyIsZero,
    /// Indicates there was an error in the config struct.
    ConfigError(ConfigError),
    RecordOverflow,
}

impl From<CliHelError> for ShakeResult {
    fn from(value: CliHelError) -> Self {
        match value {
            CliHelError::IoError => Self::IoError,
            CliHelError::RngError => Self::RngError,
        }
    }
}

impl From<TlsError> for ShakeResult {
    fn from(value: TlsError) -> Self {
        match value {
            TlsError::Alert(err) => Self::PeerError(err),
            TlsError::ReceivedAlert(err) => Self::ReceivedAlert(err),
        }
    }
}

impl From<ReadError> for ShakeResult {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::IoError => Self::IoError,
            ReadError::Timeout => Self::Timeout,
            ReadError::RecordOverflow => Self::RecordOverflow,
            ReadError::TlsError(err) => err.into()
        }
    }
}

impl From<KeyGenError> for ShakeResult {
    fn from(value: KeyGenError) -> Self {
        match value {
            KeyGenError::RngError => Self::RngError,
            KeyGenError::PrivKeyIsZero => Self::PrivKeyIsZero,
            KeyGenError::NoGroups => Self::ConfigError(ConfigError::MissingExtensions),
        }
    }
}
