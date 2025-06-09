use std::iter::Iterator;

enum CertType {
    X509 = 0,
    RawPublicKey = 2,
}

impl CertType {
    fn to_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Clone)]
pub(crate) struct CertEntry<'a> {
    data: &'a [u8],
    extensions: &'a [u8],
}

pub(crate) struct CertIter<'a> {
    current: CertEntry<'a>,
    remaining: &'a [u8],
}

impl<'a> CertIter<'a> {
    pub(crate) fn new(cert_list: &'a [u8]) -> Option<Self> {
        if cert_list.len() < 5 {
            return None;
        }
        let data_len = u32::from_be_bytes([0, cert_list[0], cert_list[1], cert_list[2]]) as usize;
        if data_len > cert_list.len() - 5 {
            return None;
        }
        let extensions_len =
            u16::from_be_bytes([cert_list[3 + data_len], cert_list[3 + data_len + 1]]) as usize;
        if extensions_len > cert_list.len() - 5 - data_len {
            return None;
        }

        Some(Self {
            current: CertEntry {
                data: &cert_list[3..][..data_len],
                extensions: &cert_list[3 + data_len + 2..][..extensions_len],
            },
            remaining: &cert_list[5 + data_len + extensions_len..],
        })
    }
}

impl<'a> Iterator for CertIter<'a> {
    type Item = CertEntry<'a>;

    fn next(&mut self) -> Option<CertEntry<'a>> {
        *self = Self::new(self.remaining)?;
        Some(self.current.clone())
    }
}
