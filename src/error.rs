use crate::alert::TurtlsAlert;
use crate::state::TurtlsConn;

/// The result of a TLS operation.
///
/// All values other than `None` represent an error.
#[derive(Debug, Clone, Copy)]
#[must_use]
#[repr(u8)]
pub enum TurtlsError {
    /// There was an error in the TLS protocol.
    ///
    /// The specific error can be accessed via `turtls_get_tls_error`.
    Tls,
    /// The peer indicated an error in the TLS protocol.
    ///
    /// The specific error can be accessed via `turtls_get_tls_error`.
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

impl Default for TurtlsError {
    fn default() -> Self {
        Self::Tls
    }
}

#[derive(Default, Debug)]
pub(crate) struct FullError {
    pub(crate) turtls_error: TurtlsError,
    pub(crate) alert: TurtlsAlert,
}

impl FullError {
    pub(crate) const fn sending_alert(alert: TurtlsAlert) -> Self {
        Self {
            turtls_error: TurtlsError::Tls,
            alert,
        }
    }

    pub(crate) const fn recving_alert(alert: TurtlsAlert) -> Self {
        Self {
            turtls_error: TurtlsError::TlsPeer,
            alert,
        }
    }

    pub(crate) fn error(turtls_error: TurtlsError) -> Self {
        Self {
            turtls_error,
            alert: TurtlsAlert::default(),
        }
    }
}

/// Returns the last error to occur.
///
/// # Safety
/// `tls_conn` must be valid
#[no_mangle]
pub unsafe extern "C" fn turtls_get_error(tls_conn: *const TurtlsConn) -> TurtlsError {
    // SAFETY: the caller guarantees that the pointer is valid.
    unsafe { (*tls_conn).gloabl_state.error.turtls_error }
}

/// Returns last TLS error to occur.
///
/// # Safety
/// `tls_conn` must be valid
#[no_mangle]
pub unsafe extern "C" fn turtls_get_tls_error(tls_conn: *const TurtlsConn) -> TurtlsAlert {
    // SAFETY: the caller guarantees that the pointer is valid.
    unsafe { (*tls_conn).gloabl_state.error.alert }
}
