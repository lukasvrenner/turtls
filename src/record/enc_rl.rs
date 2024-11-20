use std::time::Duration;

use crylib::aead::{BadData, TAG_SIZE};

use super::{ContentType, Io, ReadError, RecordLayer};
use crate::aead::TlsAead;
use crate::alert::Alert;
use crate::error::TlsError;

pub(crate) struct EncryptedRecLayer {
    pub(crate) aead: TlsAead,
    pub(crate) unenc_rl: RecordLayer,
}

impl EncryptedRecLayer {
    pub const MIN_LEN: usize = TAG_SIZE + 1;
    pub(crate) fn new(io: Io) -> Self {
        Self {
            aead: TlsAead::new_zeroed(),
            unenc_rl: RecordLayer::new(io),
        }
    }

    pub(crate) fn decrypt(&mut self) -> Result<u8, TlsError> {
        if self.unenc_rl.len() < Self::MIN_LEN {
            return Err(TlsError::Sent(Alert::DecodeError));
        }
        let (header, msg) = self.unenc_rl.buf.split_at_mut(RecordLayer::HEADER_SIZE);
        let (msg, tag) =
            msg.split_at_mut((self.unenc_rl.len - RecordLayer::HEADER_SIZE) - TAG_SIZE);
        let tag: &[u8; TAG_SIZE] = tag[..TAG_SIZE].try_into().unwrap();

        if let Err(BadData) = self.aead.decrypt_inline(msg, header, tag) {
            return Err(TlsError::Sent(Alert::BadRecordMac));
        }

        self.unenc_rl.len -= TAG_SIZE;

        let Some(padding) = self.unenc_rl.buf().iter().rev().position(|&x| x != 0) else {
            return Err(TlsError::Sent(Alert::UnexpectedMessage));
        };

        self.unenc_rl.len -= padding;
        self.unenc_rl.len -= 1;
        let msg_type = self.unenc_rl.buf()[self.unenc_rl.len() - 1];
        Ok(msg_type)
    }

    pub(crate) fn buf(&self) -> &[u8] {
        self.unenc_rl.buf()
    }

    pub(crate) fn alert_and_close(&mut self, alert: Alert) {
        todo!()
    }
}
