//! The server_name extension.

use std::ffi::CStr;

use super::{ExtList, ExtensionType};
use crate::record::{IoError, RecordLayer};
const SERVER_NAME_TYPE: u8 = 0;

impl ExtList {
    pub(super) fn server_name_len(&self) -> usize {
        if self.server_name.is_null() {
            return 0;
        }
        let str_len = unsafe { CStr::from_ptr(self.server_name).count_bytes() };
        Self::LEN_SIZE + size_of_val(&SERVER_NAME_TYPE) + Self::LEN_SIZE + str_len
    }

    pub(super) fn write_server_name(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        if self.server_name.is_null() {
            return Ok(());
        }
        rl.push_u16(ExtensionType::ServerName.as_int())?;

        let mut len = self.server_name_len();
        rl.push_u16(len as u16)?;

        len -= Self::LEN_SIZE;
        rl.push_u16(len as u16)?;

        rl.push(SERVER_NAME_TYPE)?;
        len -= 1;
        len -= Self::LEN_SIZE;
        rl.push_u16(len as u16)?;

        // SAFETY: the creator of `ExtensionList` guarantees the length and pointer are valid.
        let server_name = unsafe { CStr::from_ptr(self.server_name) }.to_bytes();
        rl.extend_from_slice(server_name)
    }
}
