use crate::cipher_suites::TurtlsCipherList;
use crate::extensions::TurtlsExts;
use crate::state::TurtlsConn;

#[repr(C)]
pub struct TurtlsConfig {
    /// The extensions to use.
    pub extensions: TurtlsExts,
    /// The cipher suites to use.
    pub cipher_suites: TurtlsCipherList,
}

impl Default for TurtlsConfig {
    fn default() -> Self {
        Self {
            extensions: TurtlsExts::default(),
            cipher_suites: TurtlsCipherList::default(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn turtls_get_config(tls_conn: *mut TurtlsConn) -> *mut TurtlsConfig {
    unsafe { &raw mut (*tls_conn).config }
}
