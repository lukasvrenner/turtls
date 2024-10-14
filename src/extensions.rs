use crate::{
    cipher_suites::{NamedGroup, SignatureScheme},
    versions::ProtocolVersion,
    Message,
};
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
    pub const fn as_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

pub fn supported_versions_client(msg_buf: &mut Message) {
    let extension_name = Extension::SupportedVersions.as_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let extension_len = (size_of::<u8>() as u16 + 1).to_be_bytes();
    msg_buf.extend_from_slice(&extension_len);

    let len = size_of::<u16>() as u8;
    msg_buf.push(len);
    msg_buf.extend_from_slice(&ProtocolVersion::TlsOnePointThree.as_be_bytes());
}

pub fn supported_versions_server(msg_buf: &mut Message) {
    let extension_name = Extension::SupportedVersions.as_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let supported_versions = ProtocolVersion::TlsOnePointThree.as_be_bytes();
    msg_buf.extend_from_slice(&supported_versions);
}

// TODO: support more algorithms and allow user to choose which to use
pub fn signature_algorithms(msg_buf: &mut Message) {
    let extension_name = Extension::SignatureAlgorithms.as_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_len);

    let len = (size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&len);

    let scheme = SignatureScheme::EcdsaSecp256r1Sha256.as_be_bytes();
    msg_buf.extend_from_slice(&scheme);
}

// TODO: support more groups and allow user to choose which to use
pub fn supported_groups(msg_buf: &mut Message) {
    let extension_name = (Extension::SupportedGroups as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_len);

    let len = (size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&len);

    let groups = NamedGroup::Secp256r1.as_be_bytes();
    msg_buf.extend_from_slice(&groups);
}

pub fn key_share_client_hello(msg_buf: &mut Message) {
    let extension_name = Extension::KeyShare.as_be_bytes();
    msg_buf.extend_from_slice(&extension_name);
    todo!()
}

fn key_share_entry(msg_buf: &mut Message) {
    let named_group = NamedGroup::Secp256r1.as_be_bytes();
    msg_buf.extend_from_slice(&named_group);
    todo!()
}
