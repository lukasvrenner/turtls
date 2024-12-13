use crate::{extensions::key_share::KeyGenError, Alert, Connection};

/// The result of a TLS operation.
///
/// All values other than `None` represent an error.
#[must_use]
#[repr(C)]
pub enum Error {
    /// There were no errors.
    None,
    /// There was an error in the TLS protocol.
    ///
    /// The specific error can be accessed via `turtls_get_tls_error`
    Tls,
    /// The peer indicated an error in the TLS protocol.
    ///
    /// The specific error can be accessed via `turtls_get_tls_error`
    TlsPeer,
    /// There was an error generating a random number.
    Rng,
    /// A read operation failed.
    ///
    /// This error IS resumable if the failure is recoverable.
    WantRead,
    /// A write operation failed.
    ///
    /// This error IS resumable if the failure is recoverable.
    WantWrite,
    /// The randomly-generated private key was zero.
    PrivKeyIsZero,
    /// One or more required extensions are missing.
    MissingExtensions,
}

/// Returns last TLS error to occur.
///
/// # Safety
/// `tls_conn` must be valid
#[no_mangle]
pub unsafe extern "C" fn turtls_get_tls_error(tls_conn: *const Connection) -> Alert {
    // SAFETY: the caller guarantees that the pointer is valid.
    unsafe { (*tls_conn).gloabl_state.alert }
}

impl From<KeyGenError> for Error {
    fn from(value: KeyGenError) -> Self {
        match value {
            KeyGenError::RngError => Self::Rng,
            KeyGenError::PrivKeyIsZero => Self::PrivKeyIsZero,
            KeyGenError::NoGroups => Self::MissingExtensions,
        }
    }
}
