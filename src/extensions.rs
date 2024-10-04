use crate::cipher_suites::{NamedGroup, SignatureScheme};
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

pub fn supported_versions_client(msg_buf: &mut Vec<u8>) -> u16 {
    let extension_name = (Extension::SupportedVersions as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let extension_len = (size_of::<u8>() as u16 + 1).to_be_bytes();
    msg_buf.extend_from_slice(&extension_len);

    let len = size_of::<u8>() as u8;
    msg_buf.push(len);
    todo!()
}

pub fn supported_versions_server(msg_buf: &mut Vec<u8>) -> u16 {
    todo!()
}

// TODO: support more algorithms and allow user to choose which to use
pub fn signature_algorithms(msg_buf: &mut Vec<u8>) {
    let extension_name = (Extension::SignatureAlgorithms as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_len);

    let len = (size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&len);

    let scheme = (SignatureScheme::EcdsaSecp256r1Sha256 as u16).to_be_bytes();
    msg_buf.extend_from_slice(&scheme);
}

// TODO: support more groups and allow user to choose which to use
pub fn supported_groups(msg_buf: &mut Vec<u8>) {
    let extension_name = (Extension::SupportedGroups as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_name);

    let extension_len = (2 * size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_len);

    let len = (size_of::<u16>() as u16).to_be_bytes();
    msg_buf.extend_from_slice(&len);

    let groups = (NamedGroup::Secp256r1 as u16).to_be_bytes();
    msg_buf.extend_from_slice(&groups);

}

pub fn key_share_client_hello(msg_buf: &mut Vec<u8>) {
    let extension_name = (Extension::KeyShare as u16).to_be_bytes();
    msg_buf.extend_from_slice(&extension_name);
    todo!()
}

fn key_share_entry(msg_buf: &mut Vec<u8>) {
    let named_group = (NamedGroup::Secp256r1 as u16).to_be_bytes();
    msg_buf.extend_from_slice(&named_group);
    let len = 65;
    todo!()
}
