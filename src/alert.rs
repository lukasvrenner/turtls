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
    pub fn from_byte(byte: u8) -> Option<Self> {
        use AlertDescription::*;
        // TODO: use inline const once stabilized
        match byte {
            x if x == CloseNotify as u8 => Some(CloseNotify),
            x if x == UnexpectedMessage as u8 => Some(UnexpectedMessage),
            x if x == BadRecordMac as u8 => Some(BadRecordMac),
            x if x == RecordOverflow as u8 => Some(RecordOverflow),
            x if x == HandshakeFailure as u8 => Some(HandshakeFailure),
            x if x == BadCert as u8 => Some(BadCert),
            x if x == UnsupportedCert as u8 => Some(UnsupportedCert),
            _ => todo!(),
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
