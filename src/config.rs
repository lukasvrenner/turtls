use crate::{cipher_suites::CipherList, extensions::ExtList};

/// The configurations to use for a specific TLS connection.
///
/// This can be automatically generated by `turtls_generate_config`.
#[repr(C)]
pub struct Config {
    /// The timeout in milliseconds to use for record layer reads during the handshake.
    ///
    /// Default value: `10000`
    pub timeout_millis: u64,
    /// The extensions to use.
    pub extensions: ExtList,
    /// The cipher suites to use.
    pub cipher_suites: CipherList,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_millis: 10_000,
            extensions: ExtList::default(),
            cipher_suites: CipherList::default(),
        }
    }
}

/// The error that is returned when there is an error in the config.
#[repr(C)]
pub enum ConfigError {
    /// No cipher suites were provided.
    MissingCipherSuites,
    /// One or more extensions is missing.
    // TODO: make this store which extension is missing
    MissingExtensions,
}
