use super::{ExtList, ExtensionType};
use crate::handshake::ShakeBuf;
use crate::state::Connection;

use std::ffi::c_char;
use std::ptr::null;

impl ExtList {
    pub(super) fn app_proto_len(&self) -> usize {
        if self.app_protos.is_null() || self.app_protos_len == 0 {
            return 0;
        }
        size_of::<u16>() + self.app_protos_len
    }
    pub(super) fn write_app_proto_client(&self, shake_buf: &mut ShakeBuf) {
        // TODO: properly handle the error
        let len: u16 = self.app_proto_len().try_into().unwrap();

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

/// Returns a pointer to name of the negotiated application protocol.
///
/// The string is nul-terminated.
///
/// # Safety
/// `connection` must be valid. If `connection` is null, a null pointer will be returned.
/// If `connection` isn't null, a null pointer will never be returned.
///
/// Lifetime: the returned pointer is valid for the entire lifetime of `connection`. If a new
/// connection is created with the same allocation, pointer is still valid and will point to the
/// new application protocol.
#[no_mangle]
pub unsafe extern "C" fn turtls_app_proto(connection: *const Connection) -> *const c_char {
    if connection.is_null() {
        return null();
    }
    // SAFETY: the caller guarantees that the pointer is valid.
    unsafe { &raw const (*connection).gloabl_state.app_proto as *const c_char }
}
