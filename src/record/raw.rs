use super::{ContentType, ReadError, RecordLayer};
use crate::alert::{Alert, AlertLevel, AlertMsg};
use crate::error::TlsError;
use crate::versions::LEGACY_PROTO_VERS;

use crylib::hash::{BufHasher, Hasher, Sha256};

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

/// The functions to use to perform IO.
///
/// This includes reading, writing, and closing the connection.
#[repr(C)]
pub struct Io {
    /// A write function.
    ///
    /// `buf`: the buffer to write.
    /// `amt`: the number of bytes to write.
    /// `ctx`: contextual data (e.g. a file descriptor).
    pub write_fn: extern "C" fn(buf: *const c_void, amt: usize, ctx: *const c_void) -> isize,
    /// A *non-blocking* read function.
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
    pub ctx: *const c_void,
}

impl Io {
    #[must_use]
    pub(crate) fn read(&self, buf: &mut [u8]) -> isize {
        (self.read_fn)(buf as *mut _ as *mut c_void, buf.len(), self.ctx)
    }

    #[must_use]
    pub(crate) fn write(&self, buf: &[u8]) -> isize {
        (self.write_fn)(buf as *const _ as *const c_void, buf.len(), self.ctx)
    }

    /// Closes the connection
    pub(crate) fn close(&self) {
        (self.close_fn)(self.ctx);
    }
}

impl RecordLayer {
    pub(crate) const LEN_SIZE: usize = 0x2;
    pub(crate) const HEADER_SIZE: usize = 0x5;
    pub(crate) const MAX_LEN: usize = 0x4000;
    pub(crate) const SUFFIX_SIZE: usize = 0x100;
    pub(crate) const BUF_SIZE: usize = Self::HEADER_SIZE + Self::MAX_LEN + Self::SUFFIX_SIZE;

    pub(crate) fn init(record: &mut MaybeUninit<Self>, msg_type: ContentType, io: Io) -> &mut Self {
        let ptr = record.write(Self {
            buf: [0; Self::BUF_SIZE],
            len: 0,
            msg_type,
            io,
            transcript: BufHasher::new(),
        });
        ptr.start();
        ptr
    }

    pub(crate) fn start_as(&mut self, msg_type: ContentType) {
        self.msg_type = msg_type;
        self.start();
    }

    pub(crate) fn start(&mut self) {
        self.buf[0] = self.msg_type.to_byte();
        self.buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        self.len = Self::HEADER_SIZE;
    }

    fn set_len(&mut self, len: u16) {
        self.buf[Self::HEADER_SIZE - Self::LEN_SIZE..Self::HEADER_SIZE]
            .copy_from_slice(&len.to_be_bytes());
    }

    pub(crate) fn finish(&mut self) {
        self.transcript
            .update_with(&self.buf[Self::HEADER_SIZE..self.len]);
        self.set_len(self.len() as u16);
    }

    pub(crate) fn finish_and_send(&mut self) {
        self.finish();
        self.io.write(&self.buf);
    }

    /// The length of the data in the buffer.
    ///
    /// This is the equivalent to `self.buf().len()`.
    pub(crate) const fn len(&self) -> usize {
        self.len - Self::HEADER_SIZE
    }

    pub(crate) fn buf(&self) -> &[u8] {
        &self.buf[Self::HEADER_SIZE..self.len]
    }

    pub(crate) fn push(&mut self, value: u8) {
        if self.len() == Self::MAX_LEN {
            self.finish_and_send();
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
        let diff = Self::MAX_LEN - self.len();

        if slice.len() <= diff {
            self.buf[self.len..][..slice.len()].copy_from_slice(slice);
            self.len += slice.len();
            return;
        }

        self.buf[self.len..].copy_from_slice(&slice[..diff]);
        self.len = Self::MAX_LEN + Self::HEADER_SIZE;

        for chunk in slice[diff..].chunks(Self::MAX_LEN) {
            self.finish_and_send();
            self.start();
            self.buf[Self::HEADER_SIZE..][..chunk.len()].copy_from_slice(chunk);
            self.len = Self::HEADER_SIZE + chunk.len();
        }
    }

    pub(crate) fn extend(&mut self, amt: usize) {
        self.extend_with(0, amt);
    }

    pub(crate) fn extend_with(&mut self, value: u8, amt: usize) {
        // TODO: can and should this be optimized?
        for _ in 0..amt {
            self.push(value);
        }
    }

    /// Reads a single record into [`RecordLayer`]'s internal buffer.
    pub(crate) fn read(
        &mut self,
        expected_type: ContentType,
        timeout: Duration,
    ) -> Result<(), ReadError> {
        let start_time = Instant::now();

        self.fill_buf(0, Self::HEADER_SIZE, timeout, start_time)?;

        let len = u16::from_be_bytes(
            self.buf[Self::HEADER_SIZE - Self::LEN_SIZE..Self::HEADER_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;

        if len > Self::MAX_LEN + Self::SUFFIX_SIZE {
            return Err(ReadError::TlsError(TlsError::Alert(Alert::RecordOverflow)));
        }

        let msg_type = self.buf[0];

        if msg_type == ContentType::Alert.to_byte() {
            // don't worry about errors because we're already handling an error
            let _ = self.fill_buf(Self::HEADER_SIZE, AlertMsg::SIZE, timeout, start_time);

            return Err(ReadError::TlsError(TlsError::ReceivedAlert(
                Alert::from_byte(self.buf[Self::HEADER_SIZE + size_of::<AlertLevel>()]),
            )));
        }

        if msg_type != expected_type.to_byte() {
            return Err(ReadError::TlsError(TlsError::Alert(
                Alert::UnexpectedMessage,
            )));
        }

        self.fill_buf(Self::HEADER_SIZE, len, timeout, start_time)?;
        self.len = len + Self::HEADER_SIZE;
        if self.buf[0] == ContentType::Handshake.to_byte() {
            self.transcript
                .update_with(&self.buf[Self::HEADER_SIZE..self.len]);
        }
        Ok(())
    }

    fn fill_buf(
        &mut self,
        start_index: usize,
        size: usize,
        timeout: Duration,
        start_time: Instant,
    ) -> Result<(), ReadError> {
        assert!(start_index + size < Self::BUF_SIZE);
        let buf = &mut self.buf[start_index..][..size];
        let mut bytes_read = 0;

        while bytes_read < size {
            let new_bytes = self.io.read(&mut buf[bytes_read..]);

            if start_time.elapsed() > timeout {
                return Err(ReadError::Timeout);
            }

            if new_bytes < 0 {
                return Err(ReadError::IoError);
            }

            bytes_read += new_bytes as usize
        }
        Ok(())
    }

    pub(crate) fn alert_and_close(&mut self, alert: Alert) {
        self.buf[0] = ContentType::Alert.to_byte();
        self.buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        self.set_len(AlertMsg::SIZE as u16);
        AlertMsg::new_in(
            &mut self.buf[Self::HEADER_SIZE..][..AlertMsg::SIZE]
                .try_into()
                .unwrap(),
            alert,
        );
        let _ = self
            .io
            .write(&self.buf[..Self::HEADER_SIZE + AlertMsg::SIZE]);
        self.io.close();
    }

    /// Same as `alert_and_close` but without using the internal buffer.
    ///
    /// This only exists due to current Rust borrow-checker limitations.
    pub(crate) fn alert_and_close_immut(&self, alert: Alert) {
        let mut alert_buf = [0; Self::HEADER_SIZE + AlertMsg::SIZE];
        alert_buf[0] = ContentType::Alert.to_byte();
        alert_buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        alert_buf[3..5].copy_from_slice(&(AlertMsg::SIZE as u16).to_be_bytes());
        AlertMsg::new_in(
            &mut self.buf[Self::HEADER_SIZE..][..AlertMsg::SIZE]
                .try_into()
                .unwrap(),
            alert,
        );
        let _ = self
            .io
            .write(&self.buf[..Self::HEADER_SIZE + AlertMsg::SIZE]);
        self.io.close();
    }

    pub(crate) fn transcript(&self) -> [u8; Sha256::HASH_SIZE] {
        self.transcript.clone().finish()
    }
}
