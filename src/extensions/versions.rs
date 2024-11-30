use super::{ExtList, ExtensionType};
use crate::record::{IoError, RecordLayer};
#[repr(u16)]
pub(crate) enum ProtocolVersion {
    #[expect(unused, reason = "SSL 3.0 is not supported")]
    SslThreeZero = 0x0300,
    #[expect(unused, reason = "TLS 1.0 is not supported")]
    TlsOneZero = 0x0301,
    #[expect(unused, reason = "SSL 1.1 is not supported")]
    TlsOneOne = 0x0302,
    TlsOneTwo = 0x0303,
    TlsOneThree = 0x0304,
}

pub(crate) const LEGACY_PROTO_VERS: ProtocolVersion = ProtocolVersion::TlsOneTwo;
const SUP_VERSIONS: [u8; 7] = {
    let mut sup_vers = [0; 7];
    [sup_vers[0], sup_vers[1]] = ExtensionType::SupportedVersions.to_be_bytes();
    // len of extension
    sup_vers[3] = 3;
    // len of versions list
    sup_vers[4] = 2;
    [sup_vers[5], sup_vers[6]] = ProtocolVersion::TlsOneThree.to_be_bytes();
    sup_vers
};

impl ProtocolVersion {
    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        self.as_int().to_be_bytes()
    }

    pub(crate) const fn as_int(self) -> u16 {
        self as u16
    }
}

impl ExtList {
    pub(super) const fn sup_versions_len(&self) -> usize {
        SUP_VERSIONS.len() - Self::HEADER_SIZE
    }

    pub(super) fn write_sup_versions_client(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        rl.extend_from_slice(&SUP_VERSIONS)
    }
}
