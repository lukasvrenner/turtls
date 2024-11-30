use core::slice;
use std::ffi::c_char;
use std::ptr::null;

use crylib::ec::{EllipticCurve, Secp256r1};
use crylib::finite_field::FieldElement;

use crate::alert::Alert;
use crate::cipher_suites::SignatureScheme;
use crate::dh::{GroupKeys, NamedGroup};
use crate::record::{IoError, RecordLayer};
use crate::versions::ProtocolVersion;

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
    #[expect(unused, reason = "AppLayerProtoReneg not yet supported")]
    AppLayerProtoReneg = 16,
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

/// The ECDSA signature algoritm over the secp256r1 (NIST-P 256) curve.
pub const ECDSA_SECP256R1: u16 = 0b0000000000000001;
/// Key exchange via ECDH on the secp256r1 (NIST-P 256) curve.
pub const SECP256R1: u16 = 0b0000000000000001;

const KEY_SHARE_LEGACY_FORM: u8 = 4;
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

const SERVER_NAME_TYPE: u8 = 0;

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
    /// `server_name` need not be null-terminated.
    pub server_name: *const c_char,

    /// The length of the `server_name` string in bytes.
    ///
    /// If `server_name_len` is `0`, the extension won't be sent.
    pub server_name_len: usize,

    /// The signature algorithms to support.
    pub sig_algs: u16,

    /// The methods to use for key exchange.
    pub sup_groups: u16,
}

impl Default for ExtList {
    fn default() -> Self {
        Self {
            server_name: null(),
            server_name_len: 0,
            sig_algs: ECDSA_SECP256R1,
            sup_groups: SECP256R1,
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
        self.write_key_share_client(rl, keys)
    }

    fn server_name_len(&self) -> usize {
        if self.server_name.is_null() || self.server_name_len == 0 {
            return 0;
        }
        Self::LEN_SIZE + size_of_val(&SERVER_NAME_TYPE) + Self::LEN_SIZE + self.server_name_len
    }

    fn write_server_name(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        if self.server_name.is_null() || self.server_name_len == 0 {
            return Ok(());
        }
        rl.push_u16(ExtensionType::ServerName.as_int())?;

        let mut len = self.server_name_len();
        rl.push_u16(len as u16)?;

        len -= Self::LEN_SIZE;
        rl.push_u16(len as u16)?;

        rl.push(SERVER_NAME_TYPE)?;
        len -= 1;
        len -= Self::LEN_SIZE;
        rl.push_u16(len as u16)?;

        // SAFETY: the creator of `ExtensionList` guarantees the length and pointer are valid.
        let server_name =
            unsafe { slice::from_raw_parts(self.server_name as *const u8, self.server_name_len) };
        rl.extend_from_slice(server_name)
    }

    const fn sig_algs_len(&self) -> usize {
        self.sig_algs.count_ones() as usize * size_of::<SignatureScheme>() + Self::LEN_SIZE
    }

    fn write_sig_algs(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        if self.sig_algs == 0 {
            return Ok(());
        }
        let len = self.sig_algs_len() as u16;
        rl.push_u16(ExtensionType::SignatureAlgorithms.as_int())?;
        rl.push_u16(len)?;

        rl.push_u16(len - Self::LEN_SIZE as u16)?;
        if self.sig_algs & ECDSA_SECP256R1 > 0 {
            rl.push_u16(SignatureScheme::EcdsaSecp256r1Sha256.as_int())?;
        }
        Ok(())
    }

    const fn sup_versions_len(&self) -> usize {
        SUP_VERSIONS.len() - Self::HEADER_SIZE
    }

    fn write_sup_versions_client(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        rl.extend_from_slice(&SUP_VERSIONS)
    }

    const fn sup_groups_len(&self) -> usize {
        Self::LEN_SIZE + self.sup_groups.count_ones() as usize * size_of::<NamedGroup>()
    }

    fn write_sup_groups(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        if self.sup_groups == 0 {
            return Ok(());
        }
        rl.push_u16(ExtensionType::SupportedGroups.as_int())?;

        let len = self.sup_groups_len();
        rl.push_u16(len as u16)?;

        rl.push_u16((len - Self::LEN_SIZE) as u16)?;

        if self.sup_groups & SECP256R1 > 0 {
            rl.push_u16(NamedGroup::Secp256r1.as_int())?;
        }
        Ok(())
    }

    fn key_share_client_len(&self) -> usize {
        if self.sup_groups & SECP256R1 == 0 {
            return 0;
        }
        // TODO: use size_of_val(&Self::LEGACY_FORM) once const-stabilized
        size_of_val(&KEY_SHARE_LEGACY_FORM)
            + 2 * size_of::<FieldElement<4, <Secp256r1 as EllipticCurve>::Order>>()
            + Self::LEN_SIZE
            + size_of::<NamedGroup>()
            + Self::LEN_SIZE
    }

    fn write_key_share_client(
        &self,
        rl: &mut RecordLayer,
        keys: &GroupKeys,
    ) -> Result<(), IoError> {
        if self.sup_groups == 0 {
            return Ok(());
        }
        rl.push_u16(ExtensionType::KeyShare.as_int())?;

        let mut len = self.key_share_client_len() as u16;
        rl.push_u16(len)?;

        len -= Self::LEN_SIZE as u16;
        rl.push_u16(len)?;

        if self.sup_groups & SECP256R1 > 0 {
            rl.extend_from_slice(&NamedGroup::Secp256r1.to_be_bytes())?;

            len -= (size_of::<NamedGroup>() + Self::LEN_SIZE) as u16;
            rl.push_u16(len)?;

            rl.push(KEY_SHARE_LEGACY_FORM)?;

            let point = Secp256r1::BASE_POINT
                .mul_scalar(&keys.secp256r1)
                .as_affine()
                .expect("private key isn't 0");

            rl.extend_from_slice(&point.x().into_inner().to_be_bytes())?;
            rl.extend_from_slice(&point.y().into_inner().to_be_bytes())?;
        }
        Ok(())
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
        let ext_type = ext[0..size_of::<ExtensionType>()].try_into().unwrap();
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
