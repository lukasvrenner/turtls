use crate::{cipher_suites::CipherSuites, extensions::Extensions};

#[repr(C)]
pub struct Config {
    pub timeout_millis: u64,
    pub extensions: Extensions,
    pub cipher_suites: CipherSuites,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_millis: 10_000,
            extensions: Extensions::default(),
            cipher_suites: CipherSuites::default(),
        }
    }
}
