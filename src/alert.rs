#[repr(u8)]
pub enum AlertLevel {
    #[expect(unused, reason = "TLS 1.3 requires all alerts to be fatal")]
    Warning = 1,
    Fatal = 2,
}

/// TLS error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Alert {
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
    InappropriateFallback = 86,
    /// The user interupted the handshake.
    UserCancelled = 90,
    /// A required extension is missing.
    MissingExtension = 109,
    /// An extension was sent that isn't supported.
    UnsupportedExtension = 110,
    /// The provided server name is unrecognized.
    UnrecognizedName = 112,
    BadCertStatusResponse = 113,
    UnknownPskIdentity = 115,
    /// A certificate is required.
    CertRequired = 116,
    /// No application protocol was provided.
    NoAppProtocol = 120,
}

impl Alert {
    pub fn from_byte(byte: u8) -> Self {
        use Alert::*;
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
    pub description: Alert,
}

impl AlertMsg {
    pub(crate) const SIZE: usize = 2;

    pub(crate) fn new(description: Alert) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; Self::SIZE] {
        [self.level as u8, self.description as u8]
    }
}
