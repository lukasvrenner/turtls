use std::ffi::c_char;
use std::ptr::null;

use crate::aead::TlsAead;
use crate::alert::TurtlsAlert;
use crate::handshake::ShakeBuf;
use crate::state::{GlobalState, UnprotShakeState};

pub mod app_proto;
pub mod key_share;
pub mod server_name;
pub mod sig_algs;
pub mod versions;

use key_share::{GroupKeys, TURTLS_SECP256R1};
use sig_algs::TURTLS_ECDSA_SECP256R1;

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
pub struct TurtlsExts {
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
    /// <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>
    pub app_protos: *const c_char,

    /// The number of supported application protocols.
    ///
    /// If `app_proto_count` is null, the extension isn't sent.
    pub app_protos_len: usize,
}

impl Default for TurtlsExts {
    fn default() -> Self {
        Self {
            server_name: null(),
            sig_algs: TURTLS_ECDSA_SECP256R1,
            sup_groups: TURTLS_SECP256R1,
            app_protos: null(),
            app_protos_len: 0,
        }
    }
}

impl TurtlsExts {
    pub(crate) const LEN_SIZE: usize = 2;
    const HEADER_SIZE: usize = size_of::<ExtensionType>() + Self::LEN_SIZE;

    /// The length of the extensions in ClientHello
    pub(crate) fn len_client(&self) -> usize {
        const fn ext_len(new_len: usize) -> usize {
            new_len + (((new_len > 0) as usize) * TurtlsExts::HEADER_SIZE)
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
    pub(crate) fn write_client(&self, shake_buf: &mut ShakeBuf, keys: &GroupKeys) {
        self.write_server_name(shake_buf);
        self.write_sig_algs(shake_buf);
        self.write_sup_versions_client(shake_buf);
        self.write_sup_groups(shake_buf);
        self.write_key_share_client(shake_buf, keys);
        self.write_app_proto_client(shake_buf);
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
        if self.exts.len() < TurtlsExts::HEADER_SIZE {
            return None;
        }
        let len = u16::from_be_bytes(
            self.exts[TurtlsExts::HEADER_SIZE - TurtlsExts::LEN_SIZE..TurtlsExts::HEADER_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        if len > self.exts.len() {
            return None;
        }
        let ext;
        (ext, self.exts) = self.exts.split_at(len + TurtlsExts::HEADER_SIZE);
        let ext_type = ext[..size_of::<ExtensionType>()].try_into().unwrap();
        Some(ExtRef {
            ext_type,
            data: &ext[TurtlsExts::HEADER_SIZE..],
        })
    }
}

pub(crate) fn parse_ser_hel_exts(
    exts: &[u8],
    shake_crypto: &mut UnprotShakeState,
    state: &mut GlobalState,
) -> Result<TlsAead, TurtlsAlert> {
    let mut maybe_aead = Err(TurtlsAlert::MissingExtension);
    let len = u16::from_be_bytes(exts[..TurtlsExts::LEN_SIZE].try_into().unwrap()) as usize;
    if len != exts.len() - TurtlsExts::LEN_SIZE {
        return Err(TurtlsAlert::DecodeError);
    }
    for ext in ExtIter::new(&exts[TurtlsExts::LEN_SIZE..]) {
        match ext.ext_type {
            x if x == &ExtensionType::SupportedVersions.to_be_bytes() => {
                versions::parse_ser(ext.data)?;
            },
            x if x == &ExtensionType::KeyShare.to_be_bytes() => {
                maybe_aead = key_share::parse_ser(ext.data, shake_crypto, state);
            },
            _ => return Err(TurtlsAlert::UnsupportedExtension),
        }
    }
    maybe_aead
}
