use super::der::{DerClass, DerIter, DerObj, DerTag, DerPrimCon, der_gen_tag};
pub(crate) fn validate_cert(cert_buf: &[u8]) -> Option<()> {
    let cert = DerIter::new(cert_buf).next()?;
    if cert.tag != DerTag::Sequence as u8 {
        return None;
    }
    let mut cert_iter = DerIter::new(cert.data);
    let tbs_cert = cert_iter.next()?;
    parse_tbs_cert(tbs_cert)?;

    let sig_alg = cert_iter.next()?;

    let sig_value = cert_iter.next()?;
    Some(())
}

fn parse_tbs_cert(tbs_cert: DerObj) -> Option<()> {
    if tbs_cert.tag != DerTag::Sequence as u8 {
        return None;
    }
    let mut tbs_iter = DerIter::new(tbs_cert.data);

    let mut next = tbs_iter.next()?;

    let version: u8;
    // version is an optional field
    if next.tag == der_gen_tag(DerClass::ContextSpecific, DerPrimCon::Constructed, 0) {
        let vers = DerIter::new(next.data).next()?;
        if vers.tag != DerTag::Integer as u8 || vers.data.len() != 1 {
            return None;
        }
        version = vers.data[0] + 1;
        next = tbs_iter.next()?;
    } else {
        version = 1;
    }
    if version != 3 {
        // TODO: return invalid version indicator
        return None;
    }
    let serial_num_obj = next;
    let signature_obj = tbs_iter.next()?;
    let issuer_obj = tbs_iter.next()?;
    let validity_obj = tbs_iter.next()?;
    let subject_obj = tbs_iter.next()?;
    let subject_pub_key_info_obj = tbs_iter.next()?;

    next = tbs_iter.next()?;

    // if get_der_num(next.tag) == 0x01 {
    //     let issuer_unique_id = next;
    //     Some(next) = tbs_iter.next() else {
    //         return Some(());
    //     }
    // }
    // if get_der_num(next.tag) == 0x02 {
    //     let subj_unique_id = next;
    //     Some(next) = tbs_iter.next() else {
    //         return Some(());
    //     }
    // }
    // if get_der_num(next.tag) == 0x03 {
    //     let extensions = next;
    // }
    Some(())
}
