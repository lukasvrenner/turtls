#[repr(u16)]
pub enum ProtocolVersion {
    SslThreePointZero = 0x0300,
    TlsOnePointZero = 0x0301,
    TlsOnePointOne = 0x0302,
    TlsOnePointTwo = 0x0303,
    TlsOnePointThree = 0x0304,
}

pub const LEGACY_PROTO_VERS: ProtocolVersion = ProtocolVersion::TlsOnePointZero;

impl ProtocolVersion {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}
