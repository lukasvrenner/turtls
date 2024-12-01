use std::ffi::c_char;
use std::ptr::null;

use crate::alert::Alert;
use crate::record::{IoError, RecordLayer};

pub mod app_proto;
pub mod key_share;
pub mod server_name;
pub mod sig_algs;
pub mod versions;
use key_share::{GroupKeys, SECP256R1};
use sig_algs::ECDSA_SECP256R1;
use versions::ProtocolVersion;

#[repr(u16)]
pub(crate) enum ExtensionType {
    ServerName = 0,
    #[expect(unused, reason = "MaxFragmentLength not yet supported")]
    MaxFragmentLength = 1,
    #[expect(unused, reason = "StatusRequest not yet supported")]
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    #[expect(unused, reason = "UseSrtp not yet supported")]
    UseSrtp = 14,
    #[expect(unused, reason = "Heartbeat not yet supported")]
    Heartbeat = 15,
    AppLayerProtoNeg = 16,
    #[expect(unused, reason = "SignedCertTimestamp not yet supported")]
    SignedCertTimestamp = 18,
    #[expect(unused, reason = "ClientCertType not yet supported")]
    ClientCertType = 19,
    #[expect(unused, reason = "ServerCertType not yet supported")]
    ServerCertType = 20,
    #[expect(unused, reason = "Padding not yet supported")]
    Padding = 21,
    #[expect(unused, reason = "PreSharedKey not yet supported")]
    PreSharedKey = 41,
    #[expect(unused, reason = "EarlyData not yet supported")]
    EarlyData = 42,
    SupportedVersions = 43,
    #[expect(unused, reason = "Cookie not yet supported")]
    Cookie = 44,
    #[expect(unused, reason = "PskExchangeModes not yet supported")]
    PskExchangeModes = 45,
    #[expect(unused, reason = "CertAuthorities not yet supported")]
    CertAuthorities = 47,
    #[expect(unused, reason = "OidFilters not yet supported")]
    OidFilters = 48,
    #[expect(unused, reason = "PostHandshakeAuth not yet supported")]
    PostHandshakeAuth = 49,
    #[expect(unused, reason = "SigAlgCert not yet supported")]
    SigAlgCert = 50,
    KeyShare = 51,
}

impl ExtensionType {
    pub(crate) const fn as_int(self) -> u16 {
        self as u16
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        self.as_int().to_be_bytes()
    }
}

/// The extensions to use in the handshake.
///
/// Refer to each extension's individual documentation for specific usage information.
#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(C)]
pub struct ExtList {
    /// The server name to send to the server or to expect from the client.
    ///
    /// If `server_name` is `null`, the extension won't be sent.
    ///
    /// `server_name` MUST be nul-terminated
    pub server_name: *const c_char,

    /// The signature algorithms to support.
    pub sig_algs: u16,

    /// The methods to use for key exchange.
    pub sup_groups: u16,

    /// A list of supported nul-terminated application protocols.
    ///
    /// Each name is encoded as a one-byte length and then the name.
    ///
    /// If `app_protos` is null, the extension isn't sent.
    ///
    /// A URL containing a list of protocol names is provided below.
    /// For example, HTTP/2 over TLS is "h2".
    ///
    /// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub app_protos: *const c_char,

    /// The number of supported application protocols.
    ///
    /// If `app_proto_count` is null, the extension isn't sent.
    pub app_protos_len: usize,
}

impl Default for ExtList {
    fn default() -> Self {
        Self {
            server_name: null(),
            sig_algs: ECDSA_SECP256R1,
            sup_groups: SECP256R1,
            app_protos: null(),
            app_protos_len: 0,
        }
    }
}

impl ExtList {
    pub(crate) const LEN_SIZE: usize = 2;
    const HEADER_SIZE: usize = size_of::<ExtensionType>() + Self::LEN_SIZE;

    /// The length of the extensions in ClientHello
    pub(crate) fn len_client(&self) -> usize {
        const fn ext_len(new_len: usize) -> usize {
            new_len + (((new_len > 0) as usize) * ExtList::HEADER_SIZE)
        }

        let mut len = 0;
        len += ext_len(self.server_name_len());
        len += ext_len(self.sig_algs_len());
        len += ext_len(self.sup_groups_len());
        len += ext_len(self.sup_versions_len());
        len += ext_len(self.key_share_client_len());
        len += ext_len(self.app_proto_len());

        len
    }

    /// Write the extensions to ClientHello.
    pub(crate) fn write_client(
        &self,
        rl: &mut RecordLayer,
        keys: &GroupKeys,
    ) -> Result<(), IoError> {
        self.write_server_name(rl)?;
        self.write_sig_algs(rl)?;
        self.write_sup_versions_client(rl)?;
        self.write_sup_groups(rl)?;
        self.write_key_share_client(rl, keys)?;
        self.write_app_proto_client(rl)
    }
}

pub(crate) struct ExtRef<'a> {
    ext_type: &'a [u8; 2],
    data: &'a [u8],
}

/// An iterator over the extensions sent by the peer.
pub(crate) struct ExtIter<'a> {
    exts: &'a [u8],
}

impl<'a> ExtIter<'a> {
    pub(crate) const fn new(exts: &'a [u8]) -> Self {
        Self { exts }
    }
}

impl<'a> Iterator for ExtIter<'a> {
    type Item = ExtRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.exts.len() < ExtList::HEADER_SIZE {
            return None;
        }
        let len = u16::from_be_bytes(
            self.exts[ExtList::HEADER_SIZE - ExtList::LEN_SIZE..ExtList::HEADER_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        if len > self.exts.len() {
            return None;
        }
        let ext;
        (ext, self.exts) = self.exts.split_at(len + ExtList::HEADER_SIZE);
        let ext_type = ext[..size_of::<ExtensionType>()].try_into().unwrap();
        Some(ExtRef {
            ext_type,
            data: &ext[ExtList::HEADER_SIZE..],
        })
    }
}

/// Returns the key share from the SeverHello extensions list.
pub(crate) fn parse_ser_hel(exts: &[u8]) -> Result<&[u8], Alert> {
    let mut key_share: &[u8] = &[];
    for ext in ExtIter::new(exts) {
        match ext.ext_type {
            x if x == &ExtensionType::SupportedVersions.to_be_bytes() => {
                if ext.data.len() != size_of::<ProtocolVersion>() {
                    return Err(Alert::DecodeError);
                }
                if ext.data[..size_of::<ProtocolVersion>()]
                    != ProtocolVersion::TlsOneThree.to_be_bytes()
                {
                    return Err(Alert::ProtocolVersion);
                }
            },
            x if x == &ExtensionType::KeyShare.to_be_bytes() => {
                key_share = ext.data;
            },
            _ => return Err(Alert::UnsupportedExtension),
        }
    }
    if key_share.len() == 0 {
        return Err(Alert::MissingExtension);
    }
    Ok(key_share)
}
