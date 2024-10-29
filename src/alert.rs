#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[derive(Debug)]
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

impl AlertDescription {
    pub fn from_byte(byte: u8) -> Self {
        use AlertDescription::*;
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

pub struct Alert {
    level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub const SIZE: usize = 2;
    pub fn new(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    pub fn new_in(buf: &mut [u8; 2], description: AlertDescription) {
        buf[0] = AlertLevel::Fatal as u8;
        buf[1] = description as u8;
    }

    pub const fn to_be_bytes(self) -> [u8; Self::SIZE] {
        [self.level as u8, self.description as u8]
    }
}
