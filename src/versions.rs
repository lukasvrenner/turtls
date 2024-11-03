#[repr(u16)]
pub(crate) enum ProtocolVersion {
    SslThreeZero = 0x0300,
    TlsOneZero = 0x0301,
    TlsOneOne = 0x0302,
    TlsOneTwo = 0x0303,
    TlsOneThree = 0x0304,
}

pub(crate) const LEGACY_PROTO_VERS: ProtocolVersion = ProtocolVersion::TlsOneTwo;

impl ProtocolVersion {
    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}
