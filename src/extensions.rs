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

pub trait Extension {
    const TAG: [u8; 2];
    const LEN_SIZE: usize = 2;
    const HEADER_SIZE: usize = 2 + Self::LEN_SIZE;
    fn len(&self) -> usize;
}

pub struct Extensions {
    pub server_name: Option<ServerName>,
    pub supported_versions: Option<SupportedVersions>,
    pub supported_groups: Option<SupportedGroups>,
    pub signature_algorithms: Option<SignatureAlgorithms>,
    pub key_share: Option<KeyShare>,
}

pub struct ServerName {

}

pub struct MaxFragmentLength {

}

pub struct StatusRequest {

}

pub struct SupportedGroups {

}

pub struct SignatureAlgorithms {

}

pub struct UseSrtp {

}

pub struct SupportedVersions {

}

impl Extension for SupportedVersions {
    const TAG: [u8; 2] = [0, 43];
    fn len(&self) -> usize {
        todo!();
    }
}

impl Extension for SupportedGroups {
    const TAG: [u8; 2] = [0, 10];
    fn len(&self) -> usize {
        todo!()
    }
}

pub struct KeyShare {

}
