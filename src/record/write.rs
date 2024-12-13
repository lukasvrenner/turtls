use super::{ContentType, RecordLayer};

use crate::aead::TlsAead;
use crate::alert::{AlertMsg, TurtlsAlert};
use crate::extensions::versions::LEGACY_PROTO_VERS;
use crate::TurtlsError;

use crylib::aead::TAG_SIZE;

pub(super) struct WriteBuf {
    buf: [u8; RecordLayer::BUF_SIZE],
    /// The length of the current record.
    ///
    /// This does not include the header.
    len: usize,
    record_bytes: usize,
    /// The total number of bytes written to IO.
    total_bytes: usize,
}

impl WriteBuf {
    pub const fn new() -> Self {
        let mut buf = Self {
            buf: [0; RecordLayer::BUF_SIZE],
            len: 0,
            record_bytes: 0,
            total_bytes: 0,
        };
        [buf.buf[1], buf.buf[2]] = LEGACY_PROTO_VERS.to_be_bytes();
        buf
    }
}

impl RecordLayer {
    fn set_msg_type(&mut self, msg_type: ContentType) {
        self.wbuf.buf[0] = msg_type.to_byte();
    }

    pub(crate) fn write_raw(
        &mut self,
        buf: &[u8],
        msg_type: ContentType,
    ) -> Result<(), TurtlsError> {
        self.set_msg_type(msg_type);
        while self.wbuf.total_bytes < buf.len() {
            let record_size = std::cmp::min(buf.len() - self.wbuf.total_bytes, Self::MAX_LEN);
            self.wbuf.buf[Self::HEADER_SIZE..][..record_size]
                .copy_from_slice(&buf[self.wbuf.total_bytes..][..record_size]);
            self.wbuf.len = record_size;
            self.finish_raw()?;
        }
        self.wbuf.total_bytes = 0;
        Ok(())
    }

    pub(crate) fn write(
        &mut self,
        buf: &[u8],
        msg_type: ContentType,
        aead: &mut TlsAead,
    ) -> Result<(), TurtlsError> {
        self.set_msg_type(ContentType::ApplicationData);
        for record in buf[self.wbuf.total_bytes..].chunks(Self::MAX_LEN) {
            self.wbuf.buf[Self::HEADER_SIZE..][..record.len()].copy_from_slice(record);
            self.wbuf.len = record.len();
            self.finish(msg_type, aead)?;
        }
        Ok(())
    }

    fn encode_len(&mut self) {
        let len = (self.wbuf.len as u16).to_be_bytes();
        self.wbuf.buf[Self::HEADER_SIZE - Self::LEN_SIZE..Self::HEADER_SIZE].copy_from_slice(&len);
    }

    fn finish_raw(&mut self) -> Result<(), TurtlsError> {
        self.encode_len();
        self.write_record()
    }

    fn finish(&mut self, msg_type: ContentType, aead: &mut TlsAead) -> Result<(), TurtlsError> {
        self.wbuf.buf[Self::HEADER_SIZE + self.wbuf.len] = msg_type.to_byte();
        self.wbuf.len += size_of::<ContentType>();
        self.wbuf.len += TAG_SIZE;
        self.encode_len();
        self.protect(aead);
        self.write_record()
    }

    fn write_record(&mut self) -> Result<(), TurtlsError> {
        while self.wbuf.record_bytes < self.wbuf.len + Self::HEADER_SIZE {
            let bytes_written = self
                .io
                .write(&self.wbuf.buf[self.wbuf.record_bytes..Self::HEADER_SIZE + self.wbuf.len])
                .ok_or(TurtlsError::WantWrite)?;
            self.wbuf.record_bytes += bytes_written as usize;
        }
        self.wbuf.total_bytes += self.wbuf.record_bytes;
        self.wbuf.record_bytes = 0;
        Ok(())
    }

    fn protect(&mut self, aead: &mut TlsAead) {
        let (header, msg) =
            self.wbuf.buf[..Self::HEADER_SIZE + self.wbuf.len].split_at_mut(Self::HEADER_SIZE);
        let (msg, tag) = msg.split_at_mut(self.wbuf.len - TAG_SIZE);
        let tag: &mut [u8; TAG_SIZE] = tag.try_into().unwrap();
        *tag = aead.encrypt_inline(msg, header);
    }

    pub(crate) fn close_raw(&mut self, alert: TurtlsAlert) {
        let _ = self.write_raw(&AlertMsg::new(alert).to_be_bytes(), ContentType::Alert);
        self.io.close();
    }

    pub(crate) fn close(&mut self, alert: TurtlsAlert, aead: &mut TlsAead) {
        let _ = self.write(
            &AlertMsg::new(alert).to_be_bytes(),
            ContentType::Alert,
            aead,
        );
        self.io.close();
    }
}
