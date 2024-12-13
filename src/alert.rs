#[repr(u8)]
pub enum AlertLevel {
    #[expect(unused, reason = "TLS 1.3 requires all alerts to be fatal")]
    Warning = 1,
    Fatal = 2,
}

/// TLS error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TurtlsAlert {
    /// The connection is being closed
    CloseNotify = 0,
    /// An unexpected message was received.
    UnexpectedMessage = 10,
    /// Record authentication failed.
    BadRecordMac = 20,
    /// The record was longer than the maximum record size.
    RecordOverflow = 22,
    /// The handshake failed for an unspecified reason.
    HandshakeFailure = 40,
    /// The provided certificate was invalid.
    BadCert = 42,
    /// The provided certificated is unsupported.
    UnsupportedCert = 43,
    /// The provided certificate has been revoked.
    CertRevoked = 44,
    /// The provided certificate has expired.
    CertExpired = 45,
    /// There was an unspecified error processing the certificate.
    CertUnknown = 46,
    /// A parameter was invalid (e.g. an elliptic curve point wasn't on the curve).
    IllegalParam = 47,
    /// The provided certificate authority is unrecognized.
    UnknownCa = 48,
    /// The sender decided not to proceed with the handshake.
    AccessDenied = 49,
    /// There was an error decoding a message.
    DecodeError = 50,
    /// There was an error decrypting a message.
    DecryptErorr = 51,
    /// The attempted protocol version is unsupported.
    ProtocolVersion = 70,
    /// The server requires more-secure parameters than those provided by the client.
    InsufficientSecurity = 71,
    /// An unrelated internal error has occured.
    InternalError = 80,
    /// An inappropriate downgrade was attempted.
    InappropriateFallback = 86,
    /// The user interupted the handshake.
    UserCancelled = 90,
    /// A required extension is missing.
    MissingExtension = 109,
    /// An extension was sent that isn't supported.
    UnsupportedExtension = 110,
    /// The provided server name is unrecognized.
    UnrecognizedName = 112,
    /// An invalid or unacceptable OCSP was provided.
    BadCertStatusResponse = 113,
    /// PSK is desired but no acceptable PSK identity is sent by the client.
    UnknownPskIdentity = 115,
    /// A certificate is required.
    CertRequired = 116,
    /// No application protocol was provided.
    NoAppProtocol = 120,
}

impl TurtlsAlert {
    pub(crate) fn from_byte(byte: u8) -> Self {
        use TurtlsAlert::*;
        // TODO: use inline const once stabilized
        match byte {
            x if x == CloseNotify as u8 => CloseNotify,
            x if x == UnexpectedMessage as u8 => UnexpectedMessage,
            x if x == BadRecordMac as u8 => BadRecordMac,
            x if x == RecordOverflow as u8 => RecordOverflow,
            x if x == HandshakeFailure as u8 => HandshakeFailure,
            x if x == BadCert as u8 => BadCert,
            x if x == UnsupportedCert as u8 => UnsupportedCert,
            x if x == CertRevoked as u8 => CertRevoked,
            x if x == CertExpired as u8 => CertExpired,
            x if x == CertUnknown as u8 => CertUnknown,
            x if x == IllegalParam as u8 => IllegalParam,
            x if x == UnknownCa as u8 => UnknownCa,
            x if x == AccessDenied as u8 => AccessDenied,
            x if x == DecodeError as u8 => DecodeError,
            x if x == DecryptErorr as u8 => DecryptErorr,
            x if x == ProtocolVersion as u8 => ProtocolVersion,
            x if x == InsufficientSecurity as u8 => InsufficientSecurity,
            x if x == InternalError as u8 => InternalError,
            x if x == InappropriateFallback as u8 => InappropriateFallback,
            x if x == UserCancelled as u8 => UserCancelled,
            x if x == MissingExtension as u8 => MissingExtension,
            x if x == UnsupportedExtension as u8 => UnsupportedExtension,
            x if x == UnrecognizedName as u8 => UnrecognizedName,
            x if x == BadCertStatusResponse as u8 => BadCertStatusResponse,
            x if x == UnknownPskIdentity as u8 => UnknownPskIdentity,
            x if x == CertRequired as u8 => CertRequired,
            x if x == NoAppProtocol as u8 => NoAppProtocol,
            _ => CloseNotify,
        }
    }
}

pub(crate) struct AlertMsg {
    level: AlertLevel,
    pub description: TurtlsAlert,
}

impl AlertMsg {
    pub(crate) const SIZE: usize = 2;

    pub(crate) fn new(description: TurtlsAlert) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; Self::SIZE] {
        [self.level as u8, self.description as u8]
    }
}

use std::ffi::{c_char, CStr};
/// Returns a string representation of the alert.
///
/// Lifetime: the returned string has a static lifetime and as such can be used for the duration of
/// the program.
#[no_mangle]
pub extern "C" fn turtls_stringify_alert(alert: TurtlsAlert) -> *const c_char {
    // use explicit type to guarantee static lifetime
    let msg: &'static CStr = match alert {
        TurtlsAlert::CloseNotify => c"closing connection",
        TurtlsAlert::UnexpectedMessage => c"unexpected message",
        TurtlsAlert::BadRecordMac => c"bad record MAC",
        TurtlsAlert::HandshakeFailure => c"handshake failed",
        TurtlsAlert::RecordOverflow => c"record overflow",
        TurtlsAlert::BadCert => c"bad certificate",
        TurtlsAlert::UnsupportedCert => c"unsupported certificate",
        TurtlsAlert::CertRevoked => c"certificate revoked",
        TurtlsAlert::CertExpired => c"certificate expired",
        TurtlsAlert::CertUnknown => c"unknown certificate",
        TurtlsAlert::IllegalParam => c"illegal parameter",
        TurtlsAlert::UnknownCa => c"unknown certificate authority",
        TurtlsAlert::AccessDenied => c"access denied",
        TurtlsAlert::DecodeError => c"decode error",
        TurtlsAlert::DecryptErorr => c"decrypt error",
        TurtlsAlert::ProtocolVersion => c"unsupported protocol version",
        TurtlsAlert::InsufficientSecurity => c"insufficient security",
        TurtlsAlert::InternalError => c"internal error",
        TurtlsAlert::InappropriateFallback => c"inappropriate fallback",
        TurtlsAlert::UserCancelled => c"user canceled",
        TurtlsAlert::MissingExtension => c"missing extension",
        TurtlsAlert::UnsupportedExtension => c"unsupported extension",
        TurtlsAlert::UnrecognizedName => c"unrecognized server name",
        TurtlsAlert::BadCertStatusResponse => c"bad certificate status response",
        TurtlsAlert::UnknownPskIdentity => c"unknown PSK identity",
        TurtlsAlert::CertRequired => c"certificate required",
        TurtlsAlert::NoAppProtocol => c"no application protocol",
    };
    msg.as_ptr()
}
