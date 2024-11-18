use std::time::Duration;

use crylib::aead::{BadData, TAG_SIZE};

use crate::aead::TlsAead;
use super::{ReadError, RecordLayer, ContentType};

pub(crate) struct EncryptedRecLayer {
    read_aead: TlsAead,
    write_aead: TlsAead,
    rl: RecordLayer,
    bytes_read: usize,
}

impl EncryptedRecLayer {
    pub(crate) fn read(&mut self, buf: &mut [u8], expected_type: ContentType, timeout: Duration) -> Result<(), EncReadError> {
        if self.bytes_read == 0 {
            self.rl.read(ContentType::ApplicationData, timeout)?;
            let (header, msg) = self.rl.buf.split_at_mut(RecordLayer::HEADER_SIZE);
            let (msg, suffix) = msg.split_at_mut(self.rl.len);
            let tag: &[u8; TAG_SIZE] = suffix[..TAG_SIZE].try_into().expect("there is enough room in record layer");
            self.read_aead.decrypt_inline(msg, header, tag)?;
            let cont_type = suffix[TAG_SIZE];
            if cont_type != expected_type.to_byte() {
                if cont_type == ContentType::Alert.to_byte() {
                    todo!();
                } else {
                    todo!();
                }
            }
        }
        let size = std::cmp::min(buf.len(), self.rl.len() - self.bytes_read);
        buf[..size].copy_from_slice(&self.rl.buf()[..size]);
        self.bytes_read += size;
        self.bytes_read %= self.rl.len();
        Ok(())
    }
}

pub(crate) enum EncReadError {
    ReadError(ReadError),
    BadData,
}

impl From<ReadError> for EncReadError {
    fn from(value: ReadError) -> Self {
        Self::ReadError(value)
    }
}

impl From<BadData> for EncReadError {
    fn from(_: BadData) -> Self {
        Self::BadData
    }
}
