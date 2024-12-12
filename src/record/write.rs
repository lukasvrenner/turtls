use super::{ContentType, IoError, RecordLayer};

use crate::aead::TlsAead;
use crate::alert::{Alert, AlertMsg};
use crate::extensions::versions::LEGACY_PROTO_VERS;

use crylib::aead::TAG_SIZE;

pub(super) struct WriteBuf {
    buf: [u8; RecordLayer::BUF_SIZE],
    /// The length of the current record.
    ///
    /// This does not include the header.
    len: usize,
    record_bytes_written: usize,
    /// The total number of bytes written to IO.
    total_bytes_written: usize,
}

impl WriteBuf {
    pub const fn new() -> Self {
        let mut buf = Self {
            buf: [0; RecordLayer::BUF_SIZE],
            len: 0,
            record_bytes_written: 0,
            total_bytes_written: 0,
        };
        [buf.buf[1], buf.buf[2]] = LEGACY_PROTO_VERS.to_be_bytes();
        buf
    }
}

impl RecordLayer {
    fn set_msg_type(&mut self, msg_type: ContentType) {
        self.wbuf.buf[0] = msg_type.to_byte();
    }

    pub(crate) fn write_raw(&mut self, buf: &[u8], msg_type: ContentType) -> Result<(), IoError> {
        self.set_msg_type(msg_type);
        while self.wbuf.total_bytes_written < buf.len() {
            let record_size =
                std::cmp::min(buf.len() - self.wbuf.total_bytes_written, Self::MAX_LEN);
            self.wbuf.buf[..record_size]
                .copy_from_slice(&buf[self.wbuf.total_bytes_written..][..record_size]);
            self.write_record()?;
        }
        self.wbuf.total_bytes_written = 0;
        Ok(())
    }

    pub(crate) fn write(
        &mut self,
        buf: &[u8],
        msg_type: ContentType,
        aead: &mut TlsAead,
    ) -> Result<(), IoError> {
        self.set_msg_type(ContentType::ApplicationData);
        for record in buf[self.wbuf.total_bytes_written..].chunks(Self::MAX_LEN) {
            self.wbuf.buf[Self::HEADER_SIZE..][..record.len()].copy_from_slice(record);
            self.wbuf.len = record.len();
            self.finish(msg_type, aead)?;
        }
        Ok(())
    }

    const fn encode_len(&mut self) {
        self.wbuf.buf[Self::HEADER_SIZE - Self::LEN_SIZE] = (self.wbuf.len >> 8) as u8;
        self.wbuf.buf[Self::HEADER_SIZE - Self::LEN_SIZE + 1] = (self.wbuf.len) as u8;
    }

    fn finish_raw(&mut self) -> Result<(), IoError> {
        self.encode_len();
        self.write_record()
    }

    fn finish(&mut self, msg_type: ContentType, aead: &mut TlsAead) -> Result<(), IoError> {
        self.wbuf.buf[Self::HEADER_SIZE + self.wbuf.len] = msg_type.to_byte();
        self.wbuf.len += size_of::<ContentType>();
        self.wbuf.len += TAG_SIZE;
        self.encode_len();
        self.protect(aead);
        self.write_record()
    }

    fn write_record(&mut self) -> Result<(), IoError> {
        while self.wbuf.record_bytes_written < self.wbuf.len + Self::HEADER_SIZE {
            match self.io.write(
                &self.wbuf.buf[self.wbuf.record_bytes_written..Self::HEADER_SIZE + self.wbuf.len],
            ) {
                ..1 => return Err(IoError),
                bytes_written => self.wbuf.record_bytes_written += bytes_written as usize,
            }
        }
        self.wbuf.total_bytes_written += self.wbuf.record_bytes_written;
        self.wbuf.record_bytes_written = 0;
        Ok(())
    }

    fn protect(&mut self, aead: &mut TlsAead) {
        let (header, msg) =
            self.wbuf.buf[..Self::HEADER_SIZE + self.wbuf.len].split_at_mut(Self::HEADER_SIZE);
        let (msg, tag) = msg.split_at_mut(self.wbuf.len - TAG_SIZE);
        let tag: &mut [u8; TAG_SIZE] = tag.try_into().unwrap();
        *tag = aead.encrypt_inline(msg, header);
    }

    pub(crate) fn close_raw(&mut self, alert: Alert) {
        let _ = self.write_raw(&AlertMsg::new(alert).to_be_bytes(), ContentType::Alert);
        self.io.close();
    }

    pub(crate) fn close(&mut self, alert: Alert, aead: &mut TlsAead) {
        let _ = self.write(
            &AlertMsg::new(alert).to_be_bytes(),
            ContentType::Alert,
            aead,
        );
        self.io.close();
    }
}
