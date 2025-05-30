use super::{ContentType, RecordLayer};
use crate::aead::TlsAead;
use crate::alert::TurtlsAlert;
use crate::error::FullError;
use crate::TurtlsError;

use crylib::aead::TAG_SIZE;

enum ReadStatus {
    /// The header has not yet been completely read. The wrapped `usize` represents the number of
    /// header byets already read from IO.
    NeedsHeader(usize),
    /// The header has been read, but some data is missing. The wrapped `usize` represents the number
    /// of bytes that have already been read from IO.
    NeedsData(usize),
    /// The entire record has been read. The wrapped `usize` contains the number of bytes that have
    /// been moved into a buffer by [`RecordLayer::read_raw`].
    Moving(usize),
}

impl ReadStatus {
    pub const fn new() -> Self {
        Self::NeedsHeader(0)
    }
}

pub(super) struct ReadBuf {
    buf: [u8; RecordLayer::BUF_SIZE],
    /// The length of the current record.
    ///
    /// This does not include the header.
    len: usize,
    status: ReadStatus,
}

impl ReadBuf {
    pub(super) const fn new() -> Self {
        Self {
            buf: [0; RecordLayer::BUF_SIZE],
            len: 0,
            status: ReadStatus::new(),
        }
    }
}

impl RecordLayer {
    pub(crate) fn msg_type(&self) -> u8 {
        self.rbuf.buf[0]
    }

    /// Reads a single record but does not process it.
    ///
    /// If an unused record is already in the buffer, a new record will not be read.
    pub(crate) fn get_raw(&mut self) -> Result<(), FullError> {
        loop {
            match self.rbuf.status {
                ReadStatus::NeedsHeader(ref mut bytes_read) => {
                    while *bytes_read < Self::HEADER_SIZE {
                        let Some(new_bytes) = self
                            .io
                            .read(&mut self.rbuf.buf[*bytes_read..Self::HEADER_SIZE])
                        else {
                            return Err(FullError::error(TurtlsError::WantRead));
                        };
                        *bytes_read += new_bytes;
                    }
                    self.rbuf.len = u16::from_be_bytes(
                        self.rbuf.buf[Self::HEADER_SIZE - Self::LEN_SIZE..Self::HEADER_SIZE]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    if self.rbuf.len > Self::MAX_LEN {
                        return Err(FullError::sending_alert(TurtlsAlert::RecordOverflow));
                    }
                    self.rbuf.status = ReadStatus::NeedsData(0);
                },
                ReadStatus::NeedsData(ref mut bytes_read) => {
                    while *bytes_read < self.rbuf.len {
                        let Some(new_bytes) = self.io.read(
                            &mut self.rbuf.buf[Self::HEADER_SIZE + *bytes_read
                                ..Self::HEADER_SIZE + self.rbuf.len],
                        ) else {
                            return Err(FullError::error(TurtlsError::WantRead));
                        };
                        *bytes_read += new_bytes;
                    }
                    self.rbuf.status = ReadStatus::Moving(0);
                },
                ReadStatus::Moving(bytes_moved) => {
                    if bytes_moved == self.rbuf.len {
                        self.rbuf.status = ReadStatus::NeedsHeader(0);
                    } else {
                        return Ok(());
                    }
                },
            }
        }
    }

    /// Reads and decrypts a single record.
    ///
    /// If an unused record is already in the buffer, a new record will not be read.
    pub(crate) fn get(&mut self, aead: &mut TlsAead) -> Result<(), FullError> {
        self.get_raw()?;

        self.deprotect(aead)
            .map_err(|alert| FullError::sending_alert(alert))
    }

    /// Decrypts the current record and remove any padding.
    fn deprotect(&mut self, aead: &mut TlsAead) -> Result<(), TurtlsAlert> {
        // Only deprotect the record if it's already protected.
        if self.msg_type() != ContentType::ApplicationData.to_byte() {
            return Ok(());
        }

        if self.rbuf.len < Self::MIN_PROT_LEN {
            return Err(TurtlsAlert::DecodeError);
        }

        let (header, msg) = self.rbuf.buf[..Self::HEADER_SIZE + self.rbuf.len]
            .split_at_mut(RecordLayer::HEADER_SIZE);
        let (msg, tag) = msg.split_at_mut(msg.len() - TAG_SIZE);
        let tag = (tag as &[u8]).try_into().unwrap();

        if aead.decrypt_inline(msg, header, tag).is_err() {
            return Err(TurtlsAlert::BadRecordMac);
        }

        self.rbuf.len -= TAG_SIZE;

        let Some(padding) = self.rbuf.buf[Self::HEADER_SIZE..][..self.rbuf.len]
            .iter()
            .rev()
            .position(|&x| x != 0)
        else {
            return Err(TurtlsAlert::UnexpectedMessage);
        };

        self.rbuf.len -= padding;
        self.rbuf.buf[0] = self.rbuf.buf[Self::HEADER_SIZE + self.rbuf.len - 1];
        self.rbuf.len -= 1;
        Ok(())
    }

    /// Reads stored data into `buf` without performing any IO.
    ///
    /// # Panics
    /// If a record is currently being retrieved, this function will panic.
    pub(crate) fn read_remaining(&mut self, buf: &mut [u8]) -> usize {
        let ReadStatus::Moving(ref mut bytes_read) = self.rbuf.status else {
            panic!("The record cannot be read because it is currently being retrieved");
        };
        let new_bytes = std::cmp::min(self.rbuf.len - *bytes_read, buf.len());
        buf[..new_bytes]
            .copy_from_slice(&self.rbuf.buf[Self::HEADER_SIZE + *bytes_read..][..new_bytes]);
        *bytes_read += new_bytes;
        new_bytes
    }

    /// Reads data into `buf` until either the entire record has been read or `buf` is full.
    ///
    /// Returns the number of bytes read.
    pub(crate) fn read_raw(&mut self, buf: &mut [u8]) -> Result<usize, FullError> {
        self.get_raw()?;
        Ok(self.read_remaining(buf))
    }

    pub(crate) fn read(&mut self, buf: &mut [u8], aead: &mut TlsAead) -> Result<usize, FullError> {
        self.get(aead)?;
        Ok(self.read_remaining(buf))
    }

    /// Discards the current record.
    pub(crate) fn discard(&mut self) {
        self.rbuf.status = ReadStatus::new();
    }

    pub(crate) fn check_alert(&self) -> Result<(), TurtlsAlert> {
        if self.msg_type() == ContentType::Alert.to_byte() {
            Err(TurtlsAlert::from_byte(self.rbuf.buf[Self::HEADER_SIZE + 1]))
        } else {
            Ok(())
        }
    }
}
