use super::der::{DerClass, DerIter, DerObj, DerTag, DerPrimCon, der_gen_tag};

use crylib::ec::ecdsa::Signature;
use crylib::ec::Secp256r1;
use crylib::big_int::UBigInt;
use crylib::finite_field::FieldElement;


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
    parse_signature(sig_value)?;
    Ok(())
}

fn parse_signature(signature: DerObj) -> Result<Signature<Secp256r1>, CertError> {
    if signature.tag != DerTag::BitString as u8 {
        return Err(CertError::ParseError);
    }
    if signature.data[0] != 0 {
        // there should never be unused bits
        return Err(CertError::ParseError);
    }
    let sig_obj = DerIter::new(&signature.data[1..]).next().ok_or(CertError::ParseError)?;
    if sig_obj.tag != DerTag::Sequence as u8 {
        return Err(CertError::ParseError);
    }
    let mut sig_iter = DerIter::new(sig_obj.data);
    let r_obj = sig_iter.next().ok_or(CertError::ParseError)?;

    if r_obj.tag != DerTag::Integer as u8 {
        return Err(CertError::ParseError);
    }

    // remove leading zeros
    let leading_bytes = r_obj.data.len().checked_sub(32).ok_or(CertError::ParseError)?;
    let r = UBigInt::<4>::from_be_bytes(r_obj.data[leading_bytes..].try_into().unwrap());
    let r = FieldElement::<4, Secp256r1>::try_new(r).ok_or(CertError::CertInvalid)?;

    let s_obj = sig_iter.next().ok_or(CertError::ParseError)?;
    if s_obj.tag != DerTag::Integer as u8 {
        return Err(CertError::ParseError);
    }

    // remove leading zeros
    let leading_bytes = s_obj.data.len().checked_sub(32).ok_or(CertError::ParseError)?;
    let s = UBigInt::<4>::from_be_bytes(s_obj.data[leading_bytes..].try_into().unwrap());
    let s = FieldElement::<4, Secp256r1>::try_new(s).ok_or(CertError::CertInvalid)?;

    Ok(Signature::new(r, s))
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

/// Determines the signature algorithm used in the certificate.
///
/// TurTLS currently only supports one signature algorithm so this function only
/// verifies that used algorithm is supported. In the future, this may return which signature
/// algorithm is chosen.
fn parse_sig_alg(sig_alg: DerObj) -> Result<(), CertError> {
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
