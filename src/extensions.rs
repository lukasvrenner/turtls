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

pub fn extension(msg_buf: &mut [u8], extension: Extension, data: &[u8]) {
    assert_eq!(msg_buf.len(), data.len() + 2 * size_of::<u16>(), "buf must exactly fit the data");
    let as_bytes = (extension as u16).to_be_bytes();
    msg_buf[..2].copy_from_slice(&as_bytes);

    assert!(data.len() <= 2, "extensions have a max of two bytes");
    let data_len = (data.len() as u16).to_be_bytes();
    msg_buf[2..][..2].copy_from_slice(&data_len);

    msg_buf[4..][..data.len()].copy_from_slice(&data);
}
