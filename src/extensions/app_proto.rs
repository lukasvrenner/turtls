use super::{ExtList, ExtensionType};
use crate::record::{IoError, RecordLayer};

use std::ffi::CStr;

impl ExtList {
    pub(super) fn app_proto_len(&self) -> usize {
        if self.app_protos.is_null() || self.app_proto_count == 0 {
            return 0;
        }
        // SAFETY: we just checked for null and the caller guarantees that `app_proto_count` is
        // valid.
        let as_slice = unsafe { std::slice::from_raw_parts(self.app_protos, self.app_proto_count) };
        let mut len = size_of::<u16>();
        for proto in as_slice {
            len += size_of::<u8>();
            len += unsafe { CStr::from_ptr(*proto) }.count_bytes();
        }
        len
    }
    pub(super) fn write_app_proto_client(&self, rl: &mut RecordLayer) -> Result<(), IoError> {
        // TODO: properly handle the error
        let len: u16 = self.app_proto_len().try_into().unwrap();

        if len == 0 {
            return Ok(());
        }
        // SAFETY: We just checked for null and the caller guarantees the string is
        // nul-terminated.
        let as_slice = unsafe { std::slice::from_raw_parts(self.app_protos, self.app_proto_count) };

        rl.push_u16(ExtensionType::AppLayerProtoNeg.as_int())?;

        rl.push_u16(len)?;
        rl.push_u16(len - size_of::<u16>() as u16)?;

        for proto in as_slice {
            // SAFETY: the caller guarntees the pointer is valid and that the string is
            // nul-terminated.
            let proto_name = unsafe { CStr::from_ptr(*proto) }.to_bytes();
            // TODO: properly handle the error
            rl.push(proto_name.len().try_into().unwrap())?;
            rl.extend_from_slice(proto_name)?;
        }
        Ok(())
    }
}
