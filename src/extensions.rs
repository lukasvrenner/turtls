use std::marker::PhantomData;

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
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
#[repr(C)]
pub struct Extensions {
    pub sig_algs: SigAlgs,
    pub sup_groups: SupGroups,
    pub sup_versions: SupVersions,
    pub max_frag_len: MaxFragLen,
}

impl Extensions {
    pub(crate) const LEN_SIZE: usize = 2;
    const EXTENSION_LEN_SIZE: usize = 2;
    const HEADER_SIZE: usize = size_of::<ExtensionType>() + Self::EXTENSION_LEN_SIZE;

    pub const fn len(&self) -> usize {
        const fn new_len(new_len: usize) -> usize {
            new_len + (((new_len > 0) as usize) * Extensions::HEADER_SIZE)
        }

        let mut len = 0;
        len += new_len(self.sig_algs.len());
        len += new_len(self.sup_groups.len());
        len += new_len(self.sup_versions.len());
        len += new_len(KeyShare::len(&self.sup_groups));

        len
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer, keys: &GroupKeys) {
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
        todo!()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MaxFragLen {
    Default = 0,
    Hex200 = 1,
    Hex400 = 2,
    Hex500 = 3,
    Hex600 = 4,
}

impl Default for MaxFragLen {
    fn default() -> Self {
        Self::Default
    }
}

impl MaxFragLen {
    pub(crate) const TAG: [u8; 2] = ExtensionType::MaxFragmentLength.to_be_bytes();

    pub(crate) const fn to_byte(self) -> u8 {
        self as u8
    }

    pub(crate)  const fn len(&self) -> usize {
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

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SupGroups {
    pub groups: u16,
}

impl SupGroups {
    pub(crate) const TAG: [u8; 2] = [0, 10];
    const LEN_SIZE: usize = 2;
    pub const SECP256R1: u16 = 0b0000000000000001;

    pub const fn len(&self) -> usize {
        self.inner_len() + Self::LEN_SIZE
    }

    const fn inner_len(&self) -> usize {
        self.groups.count_ones() as usize * size_of::<NamedGroup>()
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.groups == 0 {
            return;
        }
        let inner_len = self.inner_len();
        record_layer.extend_from_slice(&Self::TAG);
        record_layer.extend_from_slice(&((inner_len + Self::LEN_SIZE) as u16).to_be_bytes());

        record_layer.extend_from_slice(&((inner_len) as u16).to_be_bytes());

        if self.groups & Self::SECP256R1 > 0 {
            record_layer.extend_from_slice(&NamedGroup::Secp256r1.to_be_bytes());
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

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SigAlgs {
    pub algorithms: u16,
}

impl SigAlgs {
    pub const ECDSA_SECP256R1: u16 = 0b0000000000000001;
    pub const TAG: [u8; 2] = [0, 13];
    const LEN_SIZE: usize = 2;
    pub const fn len(&self) -> usize {
        self.inner_len() + Self::LEN_SIZE
    }

    const fn inner_len(&self) -> usize {
        self.algorithms.count_ones() as usize * size_of::<SignatureScheme>()
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.algorithms == 0 {
            return;
        }
        record_layer.extend_from_slice(&Self::TAG);
        record_layer.extend_from_slice(&(self.len() as u16).to_be_bytes());

        record_layer.extend_from_slice(&(self.inner_len() as u16).to_be_bytes());
        if self.algorithms & Self::ECDSA_SECP256R1 > 0 {
            record_layer.extend_from_slice(&SignatureScheme::EcdsaSecp256r1Sha256.to_be_bytes());
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
    pub(crate) const TAG: [u8; 2] = [0, 43];

    pub const fn len(&self) -> usize {
        self.inner_len() + Self::LEN_SIZE
    }

    const fn inner_len(&self) -> usize {
        self.versions.count_ones() as usize * size_of::<ProtocolVersion>()
    }

    pub(crate) fn write_to(&self, record_layer: &mut RecordLayer) {
        if self.versions == 0 {
            return;
        }
        record_layer.extend_from_slice(&Self::TAG);
        let inner_len = self.inner_len();
        record_layer.extend_from_slice(&((inner_len + Self::LEN_SIZE) as u16).to_be_bytes());

        record_layer.extend_from_slice(&(inner_len as u8).to_be_bytes());

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

pub struct KeyShare {}

impl KeyShare {
    const LEGACY_FORM: u8 = 4;
    const LEN_SIZE: usize = 2;
    const INNER_LEN_SIZE: usize = 2;
    pub(crate) const TAG: [u8; 2] = [0, 51];

    pub const fn len(groups: &SupGroups) -> usize {
        Self::inner_len(groups) + Self::LEN_SIZE
    }

    const fn inner_len(groups: &SupGroups) -> usize {
        Self::inner_inner_len(groups) + Self::INNER_LEN_SIZE + size_of::<NamedGroup>()
    }

    const fn inner_inner_len(groups: &SupGroups) -> usize {
        if groups.groups & SupGroups::SECP256R1 == 0 {
            return 0;
        }
        // TODO: use size_of_val(&Self::LEGACY_FORM) once const-stabilized
        1 + 2 * size_of::<FieldElement<<Secp256r1 as EllipticCurve>::Order>>()
    }
    pub fn write_to(record_layer: &mut RecordLayer, groups: &SupGroups, keys: &GroupKeys) {
        if groups.groups == 0 {
            return;
        }
        let mut len = Self::len(groups);
        record_layer.extend_from_slice(&Self::TAG);
        record_layer.extend_from_slice(&(len as u16).to_be_bytes());

        len -= Self::LEN_SIZE;
        record_layer.extend_from_slice(&(len as u16).to_be_bytes());

        if groups.groups & SupGroups::SECP256R1 > 0 {
            record_layer.extend_from_slice(&NamedGroup::Secp256r1.to_be_bytes());

            len -= size_of::<NamedGroup>() + Self::INNER_LEN_SIZE;
            record_layer.extend_from_slice(&(len as u16).to_be_bytes());

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
