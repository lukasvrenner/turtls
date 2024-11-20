use std::time::Duration;

use crylib::aead::{BadData, TAG_SIZE};

use super::{ContentType, Io, ReadError, RecordLayer};
use crate::aead::TlsAead;
use crate::alert::Alert;
use crate::error::TlsError;

pub(crate) struct EncryptedRecLayer {
    pub(crate) aead: TlsAead,
    pub(crate) unenc_rl: RecordLayer,
    bytes_read: usize,
}

impl EncryptedRecLayer {
    pub const MIN_LEN: usize = TAG_SIZE + 1;
    pub(crate) fn new(io: Io) -> Self {
        Self {
            aead: TlsAead::new_zeroed(),
            unenc_rl: RecordLayer::new(io),
            bytes_read: 0,
        }
    }
    pub(crate) fn read(
        &mut self,
        buf: &mut [u8],
        expected_type: ContentType,
        timeout: Duration,
    ) -> Result<(), EncReadError> {
        if self.bytes_read == 0 {
            self.unenc_rl.read(ContentType::ApplicationData, timeout)?;
            if self.unenc_rl.len() < Self::MIN_LEN {
                return Err(EncReadError::ReadError(ReadError::Alert(
                    TlsError::Sent(Alert::DecodeError),
                )));
            }

            let (header, msg) = self.unenc_rl.buf.split_at_mut(RecordLayer::HEADER_SIZE);
            let (msg, tag) = msg.split_at_mut(msg.len() - TAG_SIZE);
            let tag: &mut [u8; TAG_SIZE] = tag.try_into().unwrap();

            self.aead.decrypt_inline(msg, header, tag)?;

            let cont_type = tag[0];
            if cont_type != expected_type.to_byte() {
                if cont_type == ContentType::Alert.to_byte() {
                    todo!();
                } else {
                    todo!();
                }
            }
        }
        let size = std::cmp::min(buf.len(), self.unenc_rl.len() - self.bytes_read);
        buf[..size].copy_from_slice(&self.unenc_rl.buf()[..size]);
        self.bytes_read += size;
        self.bytes_read %= self.unenc_rl.len();
        Ok(())
    }
    pub(crate) fn alert_and_close(&mut self, alert: Alert) {
        todo!()
    }
}

#[derive(Debug)]
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
