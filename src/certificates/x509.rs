use super::der::{DerClass, DerIter, DerObj, DerTag, DerPrimCon, der_gen_tag};
pub(crate) fn validate_cert(cert_buf: &[u8]) -> Result<(), CertError> {
    let cert = DerIter::new(cert_buf).next().ok_or(CertError::ParseError)?;
    if cert.tag != DerTag::Sequence as u8 {
        return Err(CertError::ParseError);
    }
    let mut cert_iter = DerIter::new(cert.data);
    let tbs_cert = cert_iter.next().ok_or(CertError::ParseError)?;
    parse_tbs_cert(tbs_cert)?;

    let sig_alg = cert_iter.next().ok_or(CertError::ParseError)?;
    parse_sig_alg(sig_alg)?;

    let sig_value = cert_iter.next().ok_or(CertError::ParseError)?;
    Ok(())
}

fn parse_tbs_cert(tbs_cert: DerObj) -> Result<(), CertError> {
    if tbs_cert.tag != DerTag::Sequence as u8 {
        return Err(CertError::ParseError);
    }
    let mut tbs_iter = DerIter::new(tbs_cert.data);

    let mut next = tbs_iter.next().ok_or(CertError::ParseError)?;

    let version: u8;
    // version is an optional field
    if next.tag == der_gen_tag(DerClass::ContextSpecific, DerPrimCon::Constructed, 0) {
        let vers = DerIter::new(next.data).next().ok_or(CertError::ParseError)?;
        if vers.tag != DerTag::Integer as u8 || vers.data.len() != 1 {
        return Err(CertError::ParseError);
        }
        version = vers.data[0] + 1;
        next = tbs_iter.next().ok_or(CertError::ParseError)?;
    } else {
        version = 1;
    }
    if version != 3 {
        // TODO: return invalid version indicator
        return Err(CertError::UnsupportedVersion);
    }
    let serial_num_obj = next;
    let signature_obj = tbs_iter.next().ok_or(CertError::ParseError)?;
    let issuer_obj = tbs_iter.next().ok_or(CertError::ParseError)?;
    let validity = tbs_iter.next().ok_or(CertError::ParseError)?;

    validate_time(validity)?;

    let subject_obj = tbs_iter.next().ok_or(CertError::ParseError)?;
    let subject_pub_key_info_obj = tbs_iter.next().ok_or(CertError::ParseError)?;

    next = tbs_iter.next().ok_or(CertError::ParseError)?;

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
    Ok(())
}

const ECDSA_SHA256_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,];

fn parse_sig_alg(sig_alg: DerObj) -> Result<(), CertError> {
    // TODO: do this
    if sig_alg.tag != DerTag::Sequence as u8 {
        return Err(CertError::ParseError);
    }
    let mut seq = DerIter::new(sig_alg.data);
    let algorithm = seq.next().ok_or(CertError::ParseError)?;

    if algorithm.tag != DerTag::ObjIdentifier as u8 {
        return Err(CertError::ParseError);
    }

    if algorithm.data != &ECDSA_SHA256_OID {
        return Err(CertError::UnsupportedSigAlg);
    }

    let parameters = seq.next();
    Ok(())
}

#[derive(Debug)]
pub(crate) enum CertError {
    ParseError,
    CertExpired,
    CertInvalid,
    UnsupportedVersion,
    UnsupportedSigAlg,
}

fn validate_time(validity: DerObj) -> Result<(), CertError> {
    if validity.tag != DerTag::Sequence as u8 {
        return Err(CertError::ParseError);
    }
    let mut valid_iter = DerIter::new(validity.data);

    let not_before = valid_iter.next().ok_or(CertError::ParseError)?;

    if not_before.tag == DerTag::UtcTime as u8 {
        // TODO: parse and validate
    } else if not_before.tag == DerTag::GeneralizedTime as u8 {
        // TODO: parse and validate
    } else {
        return Err(CertError::ParseError);
    }

    let not_after = valid_iter.next().ok_or(CertError::ParseError)?;
    if not_after.tag == DerTag::UtcTime as u8 {
        // TODO: parse and validate
    } else if not_after.tag == DerTag::GeneralizedTime as u8 {
        // TODO: parse and validate
    } else {
        return Err(CertError::ParseError);
    }
    Ok(())
}
