use crate::alert::{Alert, AlertLevel, AlertMsg};
use crate::versions::LEGACY_PROTO_VERS;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

#[repr(C)]
pub struct Io {
    /// Any io write function.
    ///
    /// `buf`: the buffer to write.
    /// `amt`: the number of bytes to write.
    /// `ctx`: any contextual data (e.g. where to write to).
    pub write_fn: extern "C" fn(buf: *const c_void, amt: usize, ctx: *const c_void) -> isize,
    /// Any *non-blocking* io read function.
    ///
    /// `buf`: the buffer to read to.
    /// `amt`: the maximum number of bytes to read.
    /// `ctx`: any contextual data (e.g. where to read to).
    ///
    /// This function must return a negative value on error, and `0` when no bytes are read.
    pub read_fn: extern "C" fn(buf: *mut c_void, amt: usize, ctx: *const c_void) -> isize,

    /// Any function to close io.
    ///
    /// `ctx`: any contextual data (e.g. what socket to close).
    pub close_fn: extern "C" fn(ctx: *const c_void),

    /// Any contextual data.
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

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContentType {
    Invalid = 0,
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

pub(crate) struct RecordLayer {
    buf: [u8; Self::BUF_SIZE],
    len: usize,
    msg_type: ContentType,
    io: Io,
}

impl RecordLayer {
    pub(crate) const LEN_SIZE: usize = 0x2;
    pub(crate) const PREFIIX_SIZE: usize = 0x5;
    pub(crate) const MAX_LEN: usize = 0x4000;
    pub(crate) const SUFFIX_SIZE: usize = 0x100;
    pub(crate) const BUF_SIZE: usize = Self::PREFIIX_SIZE + Self::MAX_LEN + Self::SUFFIX_SIZE;

    pub(crate) fn init(record: &mut MaybeUninit<Self>, msg_type: ContentType, io: Io) -> &mut Self {
        let ptr = record.write(Self {
            buf: [0; Self::BUF_SIZE],
            len: 0,
            msg_type,
            io,
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
        self.len = Self::PREFIIX_SIZE;
    }

    fn set_len(&mut self, len: u16) {
        self.buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..Self::PREFIIX_SIZE]
            .copy_from_slice(&len.to_be_bytes());
    }

    pub(crate) fn finish(&mut self) {
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
        self.len - Self::PREFIIX_SIZE
    }

    pub(crate) fn buf(&self) -> &[u8] {
        &self.buf[Self::PREFIIX_SIZE..self.len]
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
        self.len = Self::MAX_LEN + Self::PREFIIX_SIZE;

        for chunk in slice[diff..].chunks(Self::MAX_LEN) {
            self.finish_and_send();
            self.start();
            self.buf[Self::PREFIIX_SIZE..][..chunk.len()].copy_from_slice(chunk);
            self.len = Self::PREFIIX_SIZE + chunk.len();
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

        if let Err(err) = self.fill_buf(0, Self::PREFIIX_SIZE, timeout, start_time) {
            return Err(err);
        }

        let len = u16::from_be_bytes(
            self.buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..Self::PREFIIX_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;

        if len > Self::MAX_LEN + Self::SUFFIX_SIZE {
            self.alert_and_close(Alert::RecordOverflow);
            return Err(ReadError::RecordOverflow);
        }

        let msg_type = self.buf[0];

        if msg_type == ContentType::Alert.to_byte() {
            // don't worry about errors because we're already handling an error
            let _ = self.fill_buf(Self::PREFIIX_SIZE, AlertMsg::SIZE, timeout, start_time);

            return Err(ReadError::RecievedAlert(Alert::from_byte(
                self.buf[Self::PREFIIX_SIZE + size_of::<AlertLevel>()],
            )));
        }

        if msg_type != expected_type.to_byte() {
            self.alert_and_close(Alert::UnexpectedMessage);
            return Err(ReadError::UnexpectedMessage);
        }

        self.fill_buf(Self::PREFIIX_SIZE, len, timeout, start_time)?;
        self.len = len + Self::PREFIIX_SIZE;
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
            if start_time.elapsed() > timeout {
                self.alert_and_close(Alert::CloseNotify);
                return Err(ReadError::Timeout);
            }

            let new_bytes = self.io.read(&mut buf[bytes_read..]);

            if new_bytes < 0 {
                self.alert_and_close(Alert::InternalError);
                return Err(ReadError::IoError);
            }

            bytes_read += new_bytes as usize
        }
        Ok(())
    }

    pub(crate) fn alert_and_close(&mut self, alert: Alert) -> isize {
        self.buf[0] = ContentType::Alert.to_byte();
        self.buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        self.set_len(AlertMsg::SIZE as u16);
        AlertMsg::new_in(
            &mut self.buf[Self::PREFIIX_SIZE..][..AlertMsg::SIZE]
                .try_into()
                .unwrap(),
            alert,
        );
        let io_status = self
            .io
            .write(&self.buf[..Self::PREFIIX_SIZE + AlertMsg::SIZE]);
        self.io.close();
        io_status
    }
}

#[derive(Debug)]
pub(crate) enum ReadError {
    RecordOverflow,
    IoError,
    RecievedAlert(Alert),
    UnexpectedMessage,
    Timeout,
}
