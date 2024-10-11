use libcrypto::{hash::BlockHasher, hkdf::expand};
pub fn hkdf_expand_label<const H_LEN: usize, const B_LEN: usize, const K_LEN: usize, H>(
    secret: &[u8; H_LEN],
    label: &[u8],
    context: &[u8],
) -> [u8; K_LEN]
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    let mut hkdf_label =
        Vec::with_capacity(size_of::<u16>() + 2 * size_of::<u8>() + label.len() + context.len());
    hkdf_label.extend_from_slice(&K_LEN.to_be_bytes());

    hkdf_label.push(label.len() as u8);
    hkdf_label.extend_from_slice(label);

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    expand::<H_LEN, B_LEN, K_LEN, H>(secret, &hkdf_label)
}

pub fn hkdf_label<const H_LEN: usize, const B_LEN: usize, const K_LEN: usize, H>(
    secret: &[u8; H_LEN],
    label: &[u8],
    msgs: &[u8],
) -> [u8; K_LEN]
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    hkdf_expand_label::<H_LEN, B_LEN, K_LEN, H>(secret, label, &H::hash(msgs))
}
