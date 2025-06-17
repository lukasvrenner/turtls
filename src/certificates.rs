use std::iter::Iterator;

pub(crate) mod der;
pub(crate) mod x509;

enum CertType {
    X509 = 0,
    RawPublicKey = 2,
}

impl CertType {
    fn to_byte(self) -> u8 {
        self as u8
    }
}

pub(crate) struct CertEntry<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) extensions: &'a [u8],
}

pub(crate) struct CertIter<'a> {
    cert_list: &'a [u8],
}

impl<'a> CertIter<'a> {
    pub(crate) fn new(cert_list: &'a [u8]) -> Self {
        Self {
            cert_list: cert_list,
        }
    }
}

impl<'a> Iterator for CertIter<'a> {
    type Item = CertEntry<'a>;

    fn next(&mut self) -> Option<CertEntry<'a>> {
        if self.cert_list.len() < 5 {
            return None;
        }
        let data_len =
            u32::from_be_bytes([0, self.cert_list[0], self.cert_list[1], self.cert_list[2]])
                as usize;
        if data_len > self.cert_list.len() - 5 {
            return None;
        }
        let extensions_len = u16::from_be_bytes([
            self.cert_list[3 + data_len],
            self.cert_list[3 + data_len + 1],
        ]) as usize;
        if extensions_len > self.cert_list.len() - 5 - data_len {
            return None;
        }
        let cert = CertEntry {
            data: &self.cert_list[3..][..data_len],
            extensions: &self.cert_list[3 + data_len + 2..][..extensions_len],
        };
        self.cert_list = &self.cert_list[5 + data_len + extensions_len..];
        Some(cert)
    }
}
