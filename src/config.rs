use std::ffi::c_char;

use crate::{cipher_suites::CipherList, extensions::ExtList, Connection};

#[repr(C)]
pub struct Config {
    /// The extensions to use.
    pub extensions: ExtList,
    /// The cipher suites to use.
    pub cipher_suites: CipherList,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            extensions: ExtList::default(),
            cipher_suites: CipherList::default(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn turtls_get_config(tls_conn: *mut Connection) -> *mut Config {
    unsafe { &raw mut (*tls_conn).config }
}
