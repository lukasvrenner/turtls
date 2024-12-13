use crate::cipher_suites::TurtlsCipherList;
use crate::extensions::TurtlsExts;
use crate::state::TurtlsConn;

/// Configure `TurtlsConn` connections.
///
/// This struct can be accessed via `turtls_get_config`.
///
/// Most configuration is done via bitflags. Constants are provided for each flag.
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

/// Returns a pointer to the configuration struct `tls_conn`.
#[no_mangle]
pub unsafe extern "C" fn turtls_get_config(tls_conn: *mut TurtlsConn) -> *mut TurtlsConfig {
    unsafe { &raw mut (*tls_conn).config }
}
