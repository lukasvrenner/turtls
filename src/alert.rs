#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCert = 42,
    UnsupportedCert = 43,
    CertRevoked = 44,
    CertExpired = 45,
    CertUnknown = 46,
    IllegalParam = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptErorr = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCancelled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertRequired = 116,
    NoAppProtocol = 120,
}

pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

impl Alert {
    pub const fn as_be_bytes(self) -> [u8; 2] {
        [self.level as u8, self.description as u8]
    }
}