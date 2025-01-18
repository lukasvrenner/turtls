use super::{ExtensionType, TurtlsExts};
use crate::handshake::ShakeBuf;
use crate::state::TurtlsConn;
use crate::TurtlsAlert;

use std::ffi::c_char;
use std::ptr::null;

impl TurtlsExts {
    pub(super) fn app_protos_len(&self) -> usize {
        if self.app_protos.is_null() || self.app_protos_len == 0 {
            return 0;
        }
        size_of::<u16>() + self.app_protos_len
    }
    pub(super) fn write_app_protos_client(&self, shake_buf: &mut ShakeBuf) {
        // TODO: properly handle the error
        let len: u16 = self.app_protos_len().try_into().unwrap();

        if len == 0 {
            return;
        }
        // SAFETY: We just checked for null and the caller guarantees the string is
        // nul-terminated.
        let as_slice = unsafe {
            std::slice::from_raw_parts(self.app_protos as *const u8, self.app_protos_len)
        };

        shake_buf.extend_from_slice(&ExtensionType::AppLayerProtoNeg.to_be_bytes());

        shake_buf.extend_from_slice(&len.to_be_bytes());
        shake_buf.extend_from_slice(&(len - size_of::<u16>() as u16).to_be_bytes());
        shake_buf.extend_from_slice(as_slice)
    }
}

pub(crate) fn parse_app_proto_client(
    alpn: &[u8],
    alpn_state: &mut [u8; 256],
) -> Result<(), TurtlsAlert> {
    if alpn.len() < 4 {
        return Err(TurtlsAlert::DecodeError);
    }
    let (len, alpn) = alpn.split_at(2);
    let len = u16::from_be_bytes(len.try_into().unwrap()) as usize;
    if len != alpn.len() {
        return Err(TurtlsAlert::DecodeError);
    }
    let len = alpn[0] as usize;
    let alpn = &alpn[1..];

    if len != alpn.len() {
        return Err(TurtlsAlert::DecodeError);
    }

    // `alpn.len` is guaranteed to be less than or equal to `256` because the length is encoded as
    // a single byte
    alpn_state[..alpn.len()].copy_from_slice(alpn);
    Ok(())
}

/// Returns a pointer to name of the negotiated application protocol.
///
/// The string is nul-terminated.
///
/// # Safety
/// `tls_conn` must be valid.
///
/// Lifetime: the returned pointer is valid for the entire lifetime of `connection`. If a new
/// connection is created with the same allocation, pointer is still valid and will point to the
/// new application protocol.
#[no_mangle]
pub unsafe extern "C" fn turtls_app_proto(tls_conn: *const TurtlsConn) -> *const c_char {
    if tls_conn.is_null() {
        return null();
    }
    // SAFETY: the caller guarantees that the pointer is valid.
    unsafe { &raw const (*tls_conn).gloabl_state.app_proto as *const c_char }
}
