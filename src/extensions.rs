use crylib::ec::{EllipticCurve, Secp256r1};

use crate::cipher_suites::{NamedGroup, SignatureScheme};
use crate::client_hello::ClientHello;
use crate::server_hello::ServerHello;
use crate::versions::ProtocolVersion;
use crate::State;

#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    AppLayerProtoReneg = 16,
    SignedCertTimestamp = 18,
    ClientCertType = 19,
    ServerCertType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskExchangeModes = 45,
    CertAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SigAlgCert = 50,
    KeyShare = 51,
}

impl ExtensionType {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

#[derive(Default)]
pub struct Extensions {
    pub server_name: ServerName,
    pub signature_algorithms: SignatureAlgorithms,
    pub supported_groups: SupportedGroups,
    pub supported_versions: SupportedVersions,
    pub key_share: KeyShare,
    pub max_frag_len: MaxFragmentLength,
}

impl Extensions {
    pub const LEN_SIZE: usize = 2;
    pub const HEADER_SIZE: usize = 2 + Self::LEN_SIZE;

    pub const fn len(&self) -> usize {
        const fn new_len(new_len: usize) -> usize {
            new_len + (new_len > 0) as usize * Extensions::HEADER_SIZE
        }

        let mut len = 0;
        len += new_len(self.server_name.len());
        len += new_len(self.signature_algorithms.len());
        len += new_len(self.supported_groups.len());
        len += new_len(self.supported_versions.len());
        len += new_len(self.key_share.len());

        len
    }
}

pub struct ServerName {}

impl Default for ServerName {
    fn default() -> Self {
        Self {}
    }
}

impl ServerName {
    pub const fn len(&self) -> usize {
        0
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum MaxFragmentLength {
    Nul = 0,
    Hex200 = 1,
    Hex400 = 2,
    Hex500 = 3,
    Hex600 = 4,
}

impl Default for MaxFragmentLength {
    fn default() -> Self {
        Self::Nul
    }
}

impl MaxFragmentLength {
    pub const TAG: [u8; 2] = ExtensionType::MaxFragmentLength.to_be_bytes();
    pub const fn len(&self) -> usize {
        // TODO: don't cast to u8 once const traits are stabilized
        if *self as u8 == Self::Nul as u8 {
            0
        } else {
            size_of::<MaxFragmentLength>()
        }
    }
}

pub struct StatusRequest {}

pub struct SupportedGroups {
    groups: u16,
}

impl SupportedGroups {
    pub const TAG: [u8; 2] = [0, 10];
    pub const SECP256R1: u16 = 0b0000000000000001;
    pub const fn len(&self) -> usize {
        self.groups.count_ones() as usize * size_of::<NamedGroup>()
    }
}

impl Default for SupportedGroups {
    fn default() -> Self {
        Self { groups: Self::SECP256R1 }
    }
}

pub struct SignatureAlgorithms {
    pub algorithms: u16,
}

impl SignatureAlgorithms {
    pub const ECDSA_SECP256R1: u16 = 0b0000000000000001;
    pub const TAG: [u8; 2] = [0, 13];
    pub const fn len(&self) -> usize {
        self.algorithms.count_ones() as usize * size_of::<SignatureScheme>()
    }
}

impl Default for SignatureAlgorithms {
    fn default() -> Self {
        Self { algorithms: Self::ECDSA_SECP256R1 }
    }
}

pub struct UseSrtp {}

pub struct SupportedVersions {
    pub versions: u8,
}

impl SupportedVersions {
    pub const TLS_ONE_THREE: u8 = 0b00000001;
    pub const TAG: [u8; 2] = [0, 43];
    pub const fn len(&self) -> usize {
        self.versions.count_ones() as usize * size_of::<ProtocolVersion>()
    }
}

impl Default for SupportedVersions {
    fn default() -> Self {
        Self { versions: Self::TLS_ONE_THREE }
    }
}

pub struct KeyShare {}

impl KeyShare {
    pub const fn len(&self) -> usize {
        todo!();
    }
}

impl Default for KeyShare {
    fn default() -> Self {
        Self {}
    }
}
