use crate::alert::{Alert, AlertDescription};
use crate::versions::LEGACY_PROTO_VERS;
use std::ffi::{c_int, c_void};
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
    pub ctx: *const c_void,
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

    /// Sends an alert to the peer and closes the connection.
    fn alert(&self, alert: AlertDescription) -> isize {
        let mut alert_buf = [0; RecordLayer::PREFIIX_SIZE + Alert::SIZE];

        alert_buf[0] = ContentType::Alert.to_byte();
        alert_buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        alert_buf[RecordLayer::PREFIIX_SIZE - RecordLayer::LEN_SIZE..RecordLayer::PREFIIX_SIZE]
            .copy_from_slice(&(Alert::SIZE as u16).to_be_bytes());

        Alert::new_in(
            (&mut alert_buf[RecordLayer::PREFIIX_SIZE..])
                .try_into()
                .unwrap(),
            alert,
        );

        let io_status = self.write(&alert_buf);
        self.close();
        io_status
    }
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

pub struct RecordLayer {
    buf: [u8; Self::BUF_SIZE],
    len: usize,
    msg_type: ContentType,
    io: Io,
}

impl RecordLayer {
    pub const LEN_SIZE: usize = 0x2;
    pub const PREFIIX_SIZE: usize = 0x5;
    pub const MAX_LEN: usize = 0x4000;
    pub const SUFFIX_SIZE: usize = 0x100;
    pub const BUF_SIZE: usize = Self::PREFIIX_SIZE + Self::MAX_LEN + Self::SUFFIX_SIZE;

    pub fn init(record: &mut MaybeUninit<Self>, msg_type: ContentType, io: Io) -> &mut Self {
        let ptr = record.write(Self {
            buf: [0; Self::BUF_SIZE],
            len: 0,
            msg_type,
            io,
        });
        ptr.start();
        ptr
    }

    pub fn start_as(&mut self, msg_type: ContentType) {
        self.msg_type = msg_type;
        self.start();
    }

    pub fn start(&mut self) {
        self.buf[0] = self.msg_type.to_byte();
        self.buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        self.len = Self::PREFIIX_SIZE;
    }

    pub fn finish(&mut self) {
        let len = ((self.len() - Self::PREFIIX_SIZE) as u16).to_be_bytes();
        self.buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..Self::PREFIIX_SIZE].copy_from_slice(&len);
    }

    pub fn finish_and_send(&mut self) {
        self.finish();
        self.io.write(&self.buf);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, value: u8) {
        if self.len() == Self::MAX_LEN + Self::PREFIIX_SIZE {
            self.finish_and_send();
            self.start();
        }
        self.buf[self.len] = value;
        self.len += 1;
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let diff = (Self::MAX_LEN + Self::PREFIIX_SIZE) - self.len();

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

    pub fn extend(&mut self, amt: usize) {
        self.extend_with(0, amt);
    }

    pub fn extend_with(&mut self, value: u8, amt: usize) {
        for _ in 0..amt {
            self.push(value);
        }
    }

    /// Reads a single record into `buf`.
    ///
    /// If the read takes more than `timeout`, a timeout error is returned.
    pub fn read_to(
        buf: &mut [u8; Self::MAX_LEN + Self::SUFFIX_SIZE],
        expected_type: ContentType,
        io: &Io,
        timeout: Duration,
    ) -> Result<usize, ReadError> {

        /// Read until the buffer is full or the timer runs out.
        fn fill_buff(
            buf: &mut [u8],
            io: &Io,
            timeout: Duration,
            start: Instant,
        ) -> Result<(), ReadError> {
            let mut bytes_read = 0;

            while bytes_read < buf.len() {
                if start.elapsed() > timeout {
                    io.alert(AlertDescription::CloseNotify);
                    return Err(ReadError::Timeout);
                }

                let new_bytes = io.read(&mut buf[bytes_read..]);

                if new_bytes < 0 {
                    io.alert(AlertDescription::InternalError);
                    return Err(ReadError::IoError);
                }

                bytes_read += new_bytes as usize
            }
            Ok(())
        }

        let start = Instant::now();
        let mut header_buf = [0; Self::PREFIIX_SIZE];

        if let Err(err) = fill_buff(&mut header_buf, io, timeout, start) {
            return Err(err);
        }

        let len = u16::from_be_bytes(
            header_buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..]
                .try_into()
                .unwrap(),
        ) as usize;

        if len > Self::MAX_LEN + Self::SUFFIX_SIZE {
            io.alert(AlertDescription::RecordOverflow);
            return Err(ReadError::RecordOverflow);
        }

        let msg_type = header_buf[0];

        if msg_type == ContentType::Alert.to_byte() {
            let mut alert = [0; Alert::SIZE];
            // we don't need to handle errors because we're already returning an error
            let _ = fill_buff(&mut alert, io, timeout, start);
            io.close();

            return Err(ReadError::RecievedAlert(AlertDescription::from_byte(
                alert[1],
            )));
        }

        if msg_type != expected_type.to_byte() {
            io.alert(AlertDescription::UnexpectedMessage);
            return Err(ReadError::UnexpectedMessage);
        }

        fill_buff(&mut buf[..len], io, timeout, start).map(|_| len)
    }

    /// Reads a single record into [`RecordLayer`]'s internal buffer.
    pub fn read(
        &mut self,
        expected_type: ContentType,
        timeout: Duration,
    ) -> Result<usize, ReadError> {
        Self::read_to(
            (&mut self.buf[Self::PREFIIX_SIZE..]).try_into().unwrap(),
            expected_type,
            &self.io,
            timeout,
        )
    }
}

#[derive(Debug)]
pub enum ReadError {
    RecordOverflow,
    IoError,
    RecievedAlert(AlertDescription),
    UnexpectedMessage,
    Timeout,
}
