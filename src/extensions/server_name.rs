//! The server_name extension.

use std::ffi::CStr;

use super::{ExtensionType, TurtlsExts};
use crate::handshake::ShakeBuf;
const SERVER_NAME_TYPE: u8 = 0;

impl TurtlsExts {
    pub(super) fn server_name_len(&self) -> usize {
        if self.server_name.is_null() {
            return 0;
        }
        let str_len = unsafe { CStr::from_ptr(self.server_name).count_bytes() };
        Self::LEN_SIZE + size_of_val(&SERVER_NAME_TYPE) + Self::LEN_SIZE + str_len
    }

    pub(super) fn write_server_name(&self, shake_buf: &mut ShakeBuf) {
        if self.server_name.is_null() {
            return;
        }
        shake_buf.extend_from_slice(&ExtensionType::ServerName.to_be_bytes());

        let mut len = self.server_name_len();
        shake_buf.extend_from_slice(&(len as u16).to_be_bytes());

        len -= Self::LEN_SIZE;
        shake_buf.extend_from_slice(&(len as u16).to_be_bytes());

        shake_buf.push(SERVER_NAME_TYPE);
        len -= 1;
        len -= Self::LEN_SIZE;
        shake_buf.extend_from_slice(&(len as u16).to_be_bytes());

        // SAFETY: the creator of `ExtensionList` guarantees the length and pointer are valid.
        let server_name = unsafe { CStr::from_ptr(self.server_name) }.to_bytes();
        shake_buf.extend_from_slice(server_name)
    }
}
