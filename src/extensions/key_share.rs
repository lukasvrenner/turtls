//! Diffie-Hellman key exchange.

//use crate::extensions::SupGroups;
use crylib::big_int::UBigInt;
use crylib::ec::{AffinePoint, EllipticCurve, Secp256r1};
use crylib::finite_field::FieldElement;
use getrandom::getrandom;

use super::{ExtList, ExtensionType};
use crate::record::{IoError, RecordLayer};

const KEY_SHARE_LEGACY_FORM: u8 = 4;
/// Key exchange via ECDH on the secp256r1 (NIST-P 256) curve.
pub const SECP256R1: u16 = 0b0000000000000001;

#[repr(u16)]
pub(crate) enum NamedGroup {
    Secp256r1 = 0x17,
    #[expect(unused, reason = "Secp384r1 is not yet supported")]
    Secp384r1 = 0x18,
    #[expect(unused, reason = "Secp512r1 is not yet supported")]
    Secp521r1 = 0x19,

    #[expect(unused, reason = "X25519 is not yet supported")]
    X25519 = 0x1d,
    #[expect(unused, reason = "X448 is not yet supported")]
    X448 = 0x1e,

    #[expect(unused, reason = "FFDH is not supported")]
    Ffdhe2048 = 0x100,
    #[expect(unused, reason = "FFDH is not supported")]
    Ffdhe3072 = 0x101,
    #[expect(unused, reason = "FFDH is not supported")]
    Ffdhe4096 = 0x102,
    #[expect(unused, reason = "FFDH is not supported")]
    Ffdhe6144 = 0x103,
    #[expect(unused, reason = "FFDH is not supported")]
    Ffdhe8192 = 0x104,
}

impl NamedGroup {
    pub(crate) const fn as_int(self) -> u16 {
        self as u16
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        self.as_int().to_be_bytes()
    }
}

pub(crate) struct GroupKeys {
    pub(crate) secp256r1: FieldElement<4, <Secp256r1 as EllipticCurve>::Order>,
}

impl GroupKeys {
    pub(crate) fn generate(groups: u16) -> Result<Self, KeyGenError> {
        if groups == 0 {
            return Err(KeyGenError::NoGroups);
        }
        let mut buf = [0; 32];
        getrandom(&mut buf)?;

        if buf == [0; 32] {
            return Err(KeyGenError::PrivKeyIsZero);
        }

        // SAFETY: `[u64; 4]` and `[u8; 32]` have the same memory layout.
        let as_u64s: [u64; 4] = unsafe { std::mem::transmute(buf) };
        return Ok(Self {
            secp256r1: FieldElement::<4, _>::new(UBigInt(as_u64s)),
        });
    }
}

pub(crate) enum KeyGenError {
    RngError,
    PrivKeyIsZero,
    NoGroups,
}

impl From<getrandom::Error> for KeyGenError {
    fn from(_: getrandom::Error) -> Self {
        Self::RngError
    }
}
impl ExtList {
    pub(super) fn key_share_client_len(&self) -> usize {
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

    pub(super) fn write_key_share_client(
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

    pub(super) const fn sup_groups_len(&self) -> usize {
        Self::LEN_SIZE + self.sup_groups.count_ones() as usize * size_of::<NamedGroup>()
    }
    pub(super) fn write_sup_groups(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
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
}

pub(crate) fn secp256r1_shared_secret(
    key_share: &[u8],
    group_keys: &GroupKeys,
) -> Option<[u8; 32]> {
    let raw_x = UBigInt::<4>::from_be_bytes(key_share[1..][..32].try_into().unwrap());
    let x: FieldElement<4, Secp256r1> = FieldElement::try_from(raw_x).ok()?;

    let raw_y = UBigInt::<4>::from_be_bytes(key_share[33..][..32].try_into().unwrap());
    let y: FieldElement<4, Secp256r1> = FieldElement::try_from(raw_y).ok()?;

    let mut point = AffinePoint::new(x, y)?.as_projective();
    point.mul_scalar_assign(&group_keys.secp256r1);
    let as_affine = point
        .as_affine()
        .expect("private key isn't zero and point is on curve");
    Some(as_affine.x().to_be_bytes())
}
