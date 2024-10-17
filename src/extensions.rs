use crylib::ec::{EllipticCurve, Secp256r1};

use crate::cipher_suites::{NamedGroup, SignatureScheme};
use crate::client_hello::ClientHello;
use crate::versions::ProtocolVersion;
use crate::State;

#[repr(u16)]
pub enum Extension {
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

impl Extension {
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

pub fn supported_versions_client(buf: &mut ClientHello) {
    let extension_name = Extension::SupportedVersions.to_be_bytes();
    buf.extend_from_slice(&extension_name);

    let extension_len = (size_of::<u8>() as u16 + 1).to_be_bytes();
    buf.extend_from_slice(&extension_len);

    let len = size_of::<u16>() as u8;
    buf.push(len);
    buf.extend_from_slice(&ProtocolVersion::TlsOnePointThree.to_be_bytes());
}

pub fn supported_versions_server(buf: &mut ClientHello) {
    let extension_name = Extension::SupportedVersions.to_be_bytes();
    buf.extend_from_slice(&extension_name);

    let supported_versions = ProtocolVersion::TlsOnePointThree.to_be_bytes();
    buf.extend_from_slice(&supported_versions);
}

// TODO: support more algorithms and allow user to choose which to use
pub fn signature_algorithms(buf: &mut ClientHello) {
    let extension_name = Extension::SignatureAlgorithms.to_be_bytes();
    buf.extend_from_slice(&extension_name);

    let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
    buf.extend_from_slice(&extension_len);

    let len = (size_of::<u16>() as u16).to_be_bytes();
    buf.extend_from_slice(&len);

    let scheme = SignatureScheme::EcdsaSecp256r1Sha256.to_be_bytes();
    buf.extend_from_slice(&scheme);
}

// TODO: support more groups and allow user to choose which to use
pub fn supported_groups(buf: &mut ClientHello) {
    let extension_name = (Extension::SupportedGroups as u16).to_be_bytes();
    buf.extend_from_slice(&extension_name);

    let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
    buf.extend_from_slice(&extension_len);

    let len = (size_of::<u16>() as u16).to_be_bytes();
    buf.extend_from_slice(&len);

    let groups = NamedGroup::Secp256r1.to_be_bytes();
    buf.extend_from_slice(&groups);
}

pub fn key_share_client_hello(buf: &mut ClientHello, state: &State) {
    let extension_name = Extension::KeyShare.to_be_bytes();
    buf.extend_from_slice(&extension_name);

    let original_len = buf.len();
    buf.extend_from_slice(&[0; 2]);

    secp256r1_key_share(buf, state);

    let len_diff = ((buf.len() - original_len) as u16).to_be_bytes();
    buf[original_len..][..2].copy_from_slice(&len_diff);
}

fn secp256r1_key_share(buf: &mut ClientHello, state: &State) {
    let named_group = NamedGroup::Secp256r1.to_be_bytes();
    buf.extend_from_slice(&named_group);
    buf.push(4);
    let pub_key = Secp256r1::BASE_POINT
        .as_projective()
        .mul_scalar(state.group_keys.secp256r1.inner())
        .as_affine()
        .expect("private key isn't 0");
    buf.extend_from_slice(&pub_key.x().to_be_bytes());
    buf.extend_from_slice(&pub_key.y().to_be_bytes());
}
