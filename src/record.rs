use crylib::aead::TAG_SIZE;
use crylib::hash::{BufHasher, Hasher, Sha256};

use crate::aead::TlsAead;
use crate::alert::{Alert, AlertLevel, AlertMsg};
use crate::error::TlsError;
use crate::versions::LEGACY_PROTO_VERS;

use std::ffi::c_void;
use std::time::{Duration, Instant};

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub(crate) fn to_byte(self) -> u8 {
        self as u8
    }
}

/// The functions to use to perform IO.
///
/// This includes reading, writing, and closing the connection.
#[repr(C)]
pub struct Io {
    /// A *non-blocking* write function.
    ///
    /// `write_fn` must return a negative value when a fatal error occurs and zero when a non-fatal
    /// error occurs. If no error occurs, it must return the number of bytes written.
    ///
    /// `buf`: the buffer to write.
    /// `amt`: the number of bytes to write.
    /// `ctx`: contextual data (e.g. a file descriptor).
    pub write_fn: extern "C" fn(buf: *const c_void, amt: usize, ctx: *const c_void) -> isize,
    /// A *non-blocking* read function.
    ///
    /// `read_fn` must return a negative value when a fatal error occurs and zero when a non-fatal
    /// error occurs. If no error occurs, it must return the number of bytes written.
    ///
    /// `buf`: the buffer to read to.
    /// `amt`: the maximum number of bytes to read.
    /// `ctx`: contextual data (e.g. a file descriptor).
    ///
    /// This function must return a negative value on error, and `0` when no bytes are read.
    pub read_fn: extern "C" fn(buf: *mut c_void, amt: usize, ctx: *const c_void) -> isize,

    /// A function to close the connection.
    ///
    /// `ctx`: any contextual data (e.g. what socket to close).
    pub close_fn: extern "C" fn(ctx: *const c_void),

    /// Contextual data (e.g. a file descriptor).
    ///
    /// Lifetime: this pointer must be valid for the duration of the connection.
    pub ctx: *mut c_void,
}

impl Io {
    #[must_use]
    fn read(&self, buf: &mut [u8]) -> isize {
        (self.read_fn)(buf as *mut _ as *mut c_void, buf.len(), self.ctx)
    }

    #[must_use]
    fn write(&self, buf: &[u8]) -> isize {
        (self.write_fn)(buf as *const _ as *const c_void, buf.len(), self.ctx)
    }

    /// Closes the connection
    fn close(&self) {
        (self.close_fn)(self.ctx);
    }

    fn read_full(
        &self,
        buf: &mut [u8],
        start_time: Instant,
        timeout: Duration,
    ) -> Result<(), IoError> {
        let mut bytes_read = 0;

        while bytes_read < buf.len() {
            let new_bytes = self.read(&mut buf[bytes_read..]);

            if start_time.elapsed() > timeout {
                return Err(IoError::Timeout);
            }

            if new_bytes < 0 {
                return Err(IoError::IoError);
            }

            bytes_read += new_bytes as usize
        }
        Ok(())
    }

    fn write_full(
        &self,
        buf: &[u8],
        start_time: Instant,
        timeout: Duration,
    ) -> Result<(), IoError> {
        let mut bytes_written = 0;
        while bytes_written < buf.len() {
            let new_bytes = self.write(buf);

            if start_time.elapsed() > timeout {
                return Err(IoError::Timeout);
            }

            if new_bytes < 0 {
                return Err(IoError::IoError);
            }

            bytes_written += new_bytes as usize
        }
        Ok(())
    }
}

pub(crate) enum IoError {
    IoError,
    Timeout,
}

pub(crate) struct RecordLayer {
    buf: [u8; Self::BUF_SIZE],
    /// The number of bytes in the buffer *including* the header.
    ///
    /// This is *not* the same as `self.len()`
    len: usize,
    io: Io,
    pub(crate) timeout: Duration,
    pub(crate) aead: Option<TlsAead>,
    transcript: BufHasher<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>,
}

impl RecordLayer {
    pub(crate) const LEN_SIZE: usize = 0x2;
    pub(crate) const HEADER_SIZE: usize = 0x5;
    pub(crate) const MAX_LEN: usize = 0x4000;
    pub(crate) const SUFFIX_SIZE: usize = 0x100;
    pub(crate) const BUF_SIZE: usize = Self::HEADER_SIZE + Self::MAX_LEN + Self::SUFFIX_SIZE;

    pub(crate) const MIN_PROT_LEN: usize = TAG_SIZE + 1;

    pub(crate) fn new(io: Io, timeout: Duration) -> Self {
        Self {
            buf: {
                let mut buf = [0; Self::BUF_SIZE];
                [buf[1], buf[2]] = LEGACY_PROTO_VERS.to_be_bytes();
                buf
            },
            len: 0,
            io,
            timeout,
            aead: None,
            transcript: BufHasher::new(),
        }
    }

    pub(crate) fn msg_type(&self) -> u8 {
        self.buf[0]
    }

    pub(crate) fn start_as(&mut self, msg_type: ContentType) {
        self.buf[0] = msg_type.to_byte();
        self.start();
    }

    pub(crate) fn start(&mut self) {
        debug_assert_eq!(self.buf[1..3], LEGACY_PROTO_VERS.to_be_bytes());
        self.len = Self::HEADER_SIZE;
    }

    fn encode_len(&mut self) {
        let len = (self.data_len() as u16).to_be_bytes();
        self.buf[Self::HEADER_SIZE - Self::LEN_SIZE..Self::HEADER_SIZE].copy_from_slice(&len);
    }

    pub(crate) fn finish(&mut self) -> Result<(), IoError> {
        self.transcript
            .update_with(&self.buf[Self::HEADER_SIZE..self.len]);
        self.encode_len();
        self.encrypt();
        let start = Instant::now();
        self.io.write_full(&self.buf, start, self.timeout)
    }

    /// The length of the data in the buffer.
    ///
    /// This is the equivalent to `self.buf().len()`.
    pub(crate) const fn data_len(&self) -> usize {
        self.len - Self::HEADER_SIZE
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.buf[Self::HEADER_SIZE..self.len]
    }

    pub(crate) fn push(&mut self, value: u8) {
        if self.data_len() == Self::MAX_LEN {
            self.finish();
            self.start();
        }
        self.buf[self.len] = value;
        self.len += 1;
    }

    pub(crate) fn push_u16(&mut self, value: u16) {
        self.push((value >> 8) as u8);
        self.push(value as u8);
    }

    pub(crate) fn push_u24(&mut self, value: u32) {
        self.push((value >> 16) as u8);

        self.push((value >> 8) as u8);
        self.push(value as u8);
    }

    pub(crate) fn push_u32(&mut self, value: u32) {
        self.push((value >> 24) as u8);
        self.push((value >> 16) as u8);

        self.push((value >> 8) as u8);
        self.push(value as u8);
    }

    pub(crate) fn push_u64(&mut self, value: u64) {
        self.push((value >> 56) as u8);
        self.push((value >> 48) as u8);
        self.push((value >> 40) as u8);
        self.push((value >> 32) as u8);

        self.push((value >> 24) as u8);
        self.push((value >> 16) as u8);
        self.push((value >> 8) as u8);
        self.push(value as u8);
    }

    pub(crate) fn extend_from_slice(&mut self, slice: &[u8]) {
        let diff = Self::MAX_LEN - self.data_len();

        if slice.len() <= diff {
            self.buf[self.len..][..slice.len()].copy_from_slice(slice);
            self.len += slice.len();
            return;
        }

        self.buf[self.len..].copy_from_slice(&slice[..diff]);
        self.len = Self::MAX_LEN + Self::HEADER_SIZE;

        for chunk in slice[diff..].chunks(Self::MAX_LEN) {
            self.finish();
            self.start();
            self.buf[Self::HEADER_SIZE..][..chunk.len()].copy_from_slice(chunk);
            self.len = Self::HEADER_SIZE + chunk.len();
        }
    }

    /// Reads a single record into [`RecordLayer`]'s internal buffer, decrypting and processing if
    /// necessary.
    pub(crate) fn read(&mut self) -> Result<(), ReadError> {
        self.plain_read()?;

        if let Err(alert) = self.decrypt() {
            return Err(ReadError::Alert(TlsError::Sent(alert)));
        }

        [self.buf[1], self.buf[2]] = LEGACY_PROTO_VERS.to_be_bytes();

        if self.msg_type() == ContentType::Alert.to_byte() {
            return Err(ReadError::Alert(TlsError::Received(Alert::from_byte(
                self.buf[Self::HEADER_SIZE + size_of::<AlertLevel>()],
            ))));
        }
        if self.msg_type() == ContentType::Handshake.to_byte() {
            self.transcript
                .update_with(&self.buf[Self::HEADER_SIZE..self.len]);
        }
        Ok(())
    }

    /// Reads a single record into [`RecordLayer`]'s internal buffer without decrypting or
    /// processing it.
    fn plain_read(&mut self) -> Result<(), ReadError> {
        let start_time = Instant::now();

        self.io
            .read_full(&mut self.buf[..Self::HEADER_SIZE], start_time, self.timeout)?;

        let record_len = u16::from_be_bytes([
            self.buf[Self::HEADER_SIZE - 2],
            self.buf[Self::HEADER_SIZE - 1],
        ]) as usize;

        if record_len > Self::MAX_LEN + Self::SUFFIX_SIZE {
            return Err(ReadError::Alert(TlsError::Sent(Alert::RecordOverflow)));
        }
        self.len = record_len + Self::HEADER_SIZE;

        self.io.read_full(
            &mut self.buf[Self::HEADER_SIZE..][..record_len],
            start_time,
            self.timeout,
        )?;
        Ok(())
    }

    fn decrypt(&mut self) -> Result<(), Alert> {
        if self.msg_type() != ContentType::ApplicationData.to_byte() {
            return Ok(());
        }
        let Some(ref mut aead) = self.aead else {
            return Ok(());
        };

        if self.len - Self::HEADER_SIZE < Self::MIN_PROT_LEN {
            return Err(Alert::DecodeError);
        }

        let (header, msg) = self.buf[..self.len].split_at_mut(RecordLayer::HEADER_SIZE);
        let (msg, tag) = msg.split_at_mut(msg.len() - TAG_SIZE);
        let tag = (tag as &[u8]).try_into().unwrap();

        if aead.decrypt_inline(msg, header, tag).is_err() {
            return Err(Alert::BadRecordMac);
        }

        self.len -= TAG_SIZE;

        let Some(padding) = self.data().iter().rev().position(|&x| x != 0) else {
            return Err(Alert::UnexpectedMessage);
        };

        self.len -= padding;
        self.buf[0] = self.data()[self.data_len() - 1];
        self.len -= 1;
        Ok(())
    }

    fn encrypt(&mut self) {
        let Some(ref mut aead) = self.aead else {
            return;
        };
        todo!()
    }

    pub(crate) fn close(&mut self, alert: Alert) {
        self.buf[0] = ContentType::Alert.to_byte();

        debug_assert_eq!(self.buf[1..3], LEGACY_PROTO_VERS.to_be_bytes());

        self.len = Self::HEADER_SIZE + AlertMsg::SIZE;

        [self.buf[Self::HEADER_SIZE], self.buf[Self::HEADER_SIZE + 1]] =
            AlertMsg::new(alert).to_be_bytes();

        // the return value doesn't matter because we're closing anyways
        let _ = self.finish();
        self.io.close();
    }

    pub(crate) fn transcript(&self) -> [u8; Sha256::HASH_SIZE] {
        self.transcript.clone().finish()
    }
}

#[derive(Debug)]
pub(crate) enum ReadError {
    IoError,
    Alert(TlsError),
    Timeout,
}

impl From<IoError> for ReadError {
    fn from(value: IoError) -> Self {
        match value {
            IoError::IoError => Self::IoError,
            IoError::Timeout => Self::Timeout,
        }
    }
}
