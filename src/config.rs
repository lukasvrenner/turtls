use crate::{cipher_suites::CipherList, extensions::Extensions};

#[repr(C)]
pub struct Config {
    pub timeout_millis: u64,
    pub extensions: Extensions,
    pub cipher_suites: CipherList,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_millis: 10_000,
            extensions: Extensions::default(),
            cipher_suites: CipherList::default(),
        }
    }
}
