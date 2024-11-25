use crylib::hash::Sha256;
use crylib::hkdf;

const LABEL_PREFIX: &'static [u8] = b"tls13 ";
const MAX_LABEL_LEN: usize = 12;

pub(crate) fn hkdf_expand_label(
    key: &mut [u8],
    secret: &[u8; Sha256::HASH_SIZE],
    label: &[u8],
    context: &[u8],
) {
    assert!(label.len() <= MAX_LABEL_LEN);
    assert!(context.len() <= Sha256::HASH_SIZE);

    let mut hkdf_label = [0; size_of::<u16>()
        + 2 * size_of::<u8>()
        + LABEL_PREFIX.len()
        + MAX_LABEL_LEN
        + Sha256::HASH_SIZE];

    let mut pos = 0;
    hkdf_label[pos..][..size_of::<u16>()].copy_from_slice(&(key.len() as u16).to_be_bytes());
    pos += size_of::<u16>();

    hkdf_label[pos] = (LABEL_PREFIX.len() + label.len()) as u8;
    pos += 1;

    hkdf_label[pos..][..LABEL_PREFIX.len()].copy_from_slice(LABEL_PREFIX);
    pos += LABEL_PREFIX.len();

    hkdf_label[pos..][..label.len()].copy_from_slice(label);
    pos += label.len();

    hkdf_label[pos] = Sha256::HASH_SIZE as u8;
    pos += 1;

    hkdf_label[pos..][..context.len()].copy_from_slice(context);
    pos += context.len();

    hkdf::expand::<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>(
        key,
        secret,
        &hkdf_label[..pos],
    );
}

pub(crate) fn derive_secret(
    secret: &[u8; Sha256::HASH_SIZE],
    label: &[u8],
    transcript: &[u8; Sha256::HASH_SIZE],
) -> [u8; Sha256::HASH_SIZE] {
    let mut derived = [0; Sha256::HASH_SIZE];
    hkdf_expand_label(&mut derived, secret, label, transcript);
    derived
}
