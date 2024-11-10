use core::slice;
use std::ffi::c_char;
use std::ptr::null;

use crylib::ec::{EllipticCurve, Secp256r1};
use crylib::finite_field::FieldElement;

use crate::cipher_suites::{GroupKeys, NamedGroup, SignatureScheme};
use crate::record::RecordLayer;
use crate::versions::ProtocolVersion;

#[repr(u16)]
pub(crate) enum ExtensionType {
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
#[derive(Default, PartialEq, Eq, Clone, Copy)]
#[repr(C)]
pub struct Extensions {
    /// The server name to send to the server or to expect from the client.
    ///
    /// Refer to its specific documentation for more information.
    pub server_name: ServerName,
    /// A list of signature algorithms to support.
    ///
    /// Refer to its specific documentation for more information.
    pub sig_algs: SigAlgs,
    /// A list of curves to use for key exchange.
    ///
    /// Refer to its specific documentation for more information.
    pub sup_groups: SupGroups,
    /// A list of TLS versions to support.
    ///
    /// For now, this must be set to `TLS_ONE_THREE`.
    ///
    /// Refer to its specific documentation for more information.
    pub sup_versions: SupVersions,
    /// The maximum length of a record.
    ///
    /// Refer to its specific documentation for more information.
    pub max_frag_len: MaxFragLen,
}

impl Extensions {
    /// The size of the length encoding of the sum extensions.
    pub(crate) const LEN_SIZE: usize = 2;
    /// The size of each individual extension's length encoding
    const EXTENSION_LEN_SIZE: usize = 2;
    /// The size of each extension header.
    const HEADER_SIZE: usize = size_of::<ExtensionType>() + Self::EXTENSION_LEN_SIZE;

    pub(crate) fn len(&self) -> usize {
        const fn new_len(new_len: usize) -> usize {
            new_len + (((new_len > 0) as usize) * Extensions::HEADER_SIZE)
        }

        let mut len = 0;
        len += new_len(self.server_name.len());
        len += new_len(self.sig_algs.len());
        len += new_len(self.sup_groups.len());
        len += new_len(self.sup_versions.len());
        len += new_len(KeyShare::len(&self.sup_groups));

        len
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer, keys: &GroupKeys) {
        self.server_name.write_to(record_layer);
        self.sig_algs.write_to(record_layer);
        self.sup_versions.write_to(record_layer);
        self.sup_groups.write_to(record_layer);
        KeyShare::write_to(record_layer, &self.sup_groups, keys);
    }
}

pub(crate) struct ExtensionsRef<'a> {
    rm_me: &'a (),
}

impl<'a> ExtensionsRef<'a> {
    pub(crate) fn parse(extensions: &'a [u8]) -> Self {
        todo!("parse extensions");
    }
}

/// The server name to send to the server or expect from the client.
///
/// If no server name is to be sent or expected, set `name` to `NULL` and `len` to `0`.
/// By default, no name will be sent or expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ServerName {
    /// The name of the server.
    ///
    /// The string need not be null-terminated.
    ///
    /// Lifetime: this pointer must be valid for the duration of the handshake.
    pub name: *const c_char,
    /// The length of the server name in bytes.
    pub len: usize,
}

impl ServerName {
    const NAME_TYPE: u8 = 0;
    const TAG: ExtensionType = ExtensionType::ServerName;
    const LEN_SIZE: usize = 2;
    const INNER_LEN_SIZE: usize = 2;

    pub(crate) fn len(&self) -> usize {
        if self.name.is_null() {
            return 0;
        }
        Self::LEN_SIZE + size_of_val(&Self::NAME_TYPE) + Self::INNER_LEN_SIZE + self.len
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.name.is_null() || self.len == 0 {
            return;
        }
        record_layer.push_u16(Self::TAG.as_int());

        let mut len = self.len();
        record_layer.push_u16(len as u16);

        len -= Self::LEN_SIZE;
        record_layer.push_u16(len as u16);

        record_layer.push(Self::NAME_TYPE);
        len -= size_of_val(&Self::NAME_TYPE);
        len -= Self::INNER_LEN_SIZE;
        record_layer.push_u16(len as u16);

        // SAFETY: the creator of `ServerName` guarantees the length and pointer are valid.
        let server_name = unsafe { slice::from_raw_parts(self.name as *const u8, self.len) };
        record_layer.extend_from_slice(server_name);
    }
}

impl Default for ServerName {
    fn default() -> Self {
        Self {
            name: null(),
            len: 0,
        }
    }
}

/// The maximum length of a record.
///
/// This is useful in constrained environments.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MaxFragLen {
    /// Use the default record length of 0x4000 bytes.
    Default = 0,
    /// 0x200 bytes.
    Hex200 = 1,
    /// 0x400 bytes.
    Hex400 = 2,
    /// 0x500 bytes.
    Hex500 = 3,
    /// 0x600 bytes.
    Hex600 = 4,
}

impl Default for MaxFragLen {
    fn default() -> Self {
        Self::Default
    }
}

impl MaxFragLen {
    pub(crate) const TAG: ExtensionType = ExtensionType::MaxFragmentLength;

    pub(crate) const fn to_byte(self) -> u8 {
        self as u8
    }

    pub(crate) const fn len(&self) -> usize {
        // TODO: don't cast to u8 once const traits are stabilized
        if *self as u8 == Self::Default as u8 {
            return 0;
        }
        size_of::<MaxFragLen>()
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if *self == Self::Default {
            return;
        }
        record_layer.extend_from_slice(&ExtensionType::MaxFragmentLength.to_be_bytes());
        record_layer.extend_from_slice(&(size_of::<MaxFragLen>() as u16).to_be_bytes());
        record_layer.push(self.to_byte());
    }
}

/// A list of curves to use for key exchange.
///
/// Use bit-OR to turn an option on and bit-NAND to turn an option off.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SupGroups {
    #[allow(missing_docs)]
    pub groups: u16,
}

impl SupGroups {
    const TAG: ExtensionType = ExtensionType::SupportedGroups;
    const LEN_SIZE: usize = 2;
    /// NIST-P 256.
    ///
    /// This is a reasonable default curve to enable.
    pub const SECP256R1: u16 = 0b0000000000000001;

    pub(crate) const fn len(&self) -> usize {
        self.groups.count_ones() as usize * size_of::<NamedGroup>() + Self::LEN_SIZE
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.groups == 0 {
            return;
        }
        record_layer.push_u16(Self::TAG.as_int());

        let len = self.len();
        record_layer.push_u16(len as u16);

        record_layer.push_u16((len - Self::LEN_SIZE) as u16);

        if self.groups & Self::SECP256R1 > 0 {
            record_layer.push_u16(NamedGroup::Secp256r1.as_int());
        }
    }
}

impl Default for SupGroups {
    fn default() -> Self {
        Self {
            groups: Self::SECP256R1,
        }
    }
}

/// A list of algorithms to use for signatures.
///
/// Use bit-OR to turn an option on and bit-NAND to turn an option off.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SigAlgs {
    #[allow(missing_docs)]
    pub algorithms: u16,
}

impl SigAlgs {
    /// The Elliptic Curve Digital Signature Algorithm with curve Secp256r1 (NIST-P 256).
    pub const ECDSA_SECP256R1: u16 = 0b0000000000000001;
    const TAG: ExtensionType = ExtensionType::SignatureAlgorithms;
    const LEN_SIZE: usize = 2;

    pub(crate) const fn len(&self) -> usize {
        self.algorithms.count_ones() as usize * size_of::<SignatureScheme>() + Self::LEN_SIZE
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.algorithms == 0 {
            return;
        }
        let len = self.len() as u16;
        record_layer.push_u16(Self::TAG.as_int());
        record_layer.push_u16(len);

        record_layer.push_u16(len - Self::LEN_SIZE as u16);
        if self.algorithms & Self::ECDSA_SECP256R1 > 0 {
            record_layer.push_u16(SignatureScheme::EcdsaSecp256r1Sha256.as_int());
        }
    }
}

impl Default for SigAlgs {
    fn default() -> Self {
        Self {
            algorithms: Self::ECDSA_SECP256R1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct UseSrtp {}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SupVersions {
    pub versions: u8,
}

impl SupVersions {
    pub const TLS_ONE_THREE: u8 = 0b00000001;
    const LEN_SIZE: usize = 1;
    const TAG: [u8; 2] = [0, 43];

    pub(crate) const fn len(&self) -> usize {
        self.versions.count_ones() as usize * size_of::<ProtocolVersion>() + Self::LEN_SIZE
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.versions == 0 {
            return;
        }
        record_layer.extend_from_slice(&Self::TAG);
        let len = self.len();
        record_layer.push_u16(len as u16);

        record_layer.push((len - Self::LEN_SIZE) as u8);

        if self.versions & Self::TLS_ONE_THREE > 0 {
            record_layer.extend_from_slice(&ProtocolVersion::TlsOneThree.to_be_bytes());
        }
    }
}

impl Default for SupVersions {
    fn default() -> Self {
        Self {
            versions: Self::TLS_ONE_THREE,
        }
    }
}

pub(crate) struct KeyShare {}

impl KeyShare {
    const LEGACY_FORM: u8 = 4;
    const LEN_SIZE: usize = 2;
    const INNER_LEN_SIZE: usize = 2;
    const TAG: ExtensionType = ExtensionType::KeyShare;

    pub(crate) const fn len(groups: &SupGroups) -> usize {
        if groups.groups & SupGroups::SECP256R1 == 0 {
            return 0;
        }
        // TODO: use size_of_val(&Self::LEGACY_FORM) once const-stabilized
        1 + 2 * size_of::<FieldElement<4, <Secp256r1 as EllipticCurve>::Order>>()
            + Self::INNER_LEN_SIZE
            + size_of::<NamedGroup>()
            + Self::LEN_SIZE
    }

    pub(crate) fn write_to(record_layer: &mut RecordLayer, groups: &SupGroups, keys: &GroupKeys) {
        if groups.groups == 0 {
            return;
        }
        record_layer.push_u16(Self::TAG.as_int());

        let mut len = Self::len(groups) as u16;
        record_layer.push_u16(len);

        len -= Self::LEN_SIZE as u16;
        record_layer.push_u16(len);

        if groups.groups & SupGroups::SECP256R1 > 0 {
            record_layer.extend_from_slice(&NamedGroup::Secp256r1.to_be_bytes());

            len -= (size_of::<NamedGroup>() + Self::INNER_LEN_SIZE) as u16;
            record_layer.push_u16(len);

            record_layer.push(Self::LEGACY_FORM);

            let point = Secp256r1::BASE_POINT
                .mul_scalar(&keys.secp256r1)
                .as_affine()
                .expect("private key isn't 0");

            record_layer.extend_from_slice(&point.x().into_inner().to_be_bytes());
            record_layer.extend_from_slice(&point.y().into_inner().to_be_bytes());
        }
    }
}

impl Default for KeyShare {
    fn default() -> Self {
        Self {}
    }
}
