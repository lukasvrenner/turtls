use std::ffi::c_char;

use crate::{cipher_suites::CipherList, extensions::ExtList, Connection};

pub(crate) struct Config {
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
pub unsafe extern "C" fn turtls_set_server_name(connection: *mut Connection, sn: *const c_char) {
    if connection.is_null() {
        return;
    }
    // SAFETY: the caller guarantees that `connection` is valid.
    unsafe {
        (*connection).config.extensions.server_name = sn;
    }
}

#[no_mangle]
pub unsafe extern "C" fn turtls_set_app_protos(
    connection: *mut Connection,
    ap: *const c_char,
    ap_len: usize,
) {
    if connection.is_null() {
        return;
    }
    // SAFETY: the caller guarantees that `connection` is valid.
    unsafe {
        (*connection).config.extensions.app_protos = ap;
        (*connection).config.extensions.app_protos_len = ap_len;
    }
}
