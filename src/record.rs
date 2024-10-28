use crate::aead::AeadWriter;
use crate::alert::{Alert, AlertDescription};
use crate::state;
use crate::versions::LEGACY_PROTO_VERS;
use crylib::aead;
use std::ffi::{c_int, c_void};
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};
use std::usize;

#[repr(C)]
pub struct Io {
    pub write_fn: extern "C" fn(buf: *const c_void, amt: usize, ctx: *const c_void) -> isize,
    pub read_fn: extern "C" fn(buf: *mut c_void, amt: usize, ctx: *const c_void) -> isize,
    pub poll_fn: extern "C" fn(ctx: *const c_void, timeout: c_int) -> c_int,
    pub close_fn: extern "C" fn(ctx: *const c_void),
    pub ctx: *const c_void,
}

impl Io {
    pub fn read(&self, buf: &mut [u8]) -> isize {
        (self.read_fn)(buf as *mut _ as *mut c_void, buf.len(), self.ctx)
    }

    pub fn write(&self, buf: &[u8]) -> isize {
        (self.write_fn)(buf as *const _ as *const c_void, buf.len(), self.ctx)
    }

    pub fn close(&self) {
        (self.close_fn)(self.ctx);
    }

    pub fn poll(&self, timeout: Duration) -> i32 {
        (self.poll_fn)(self.ctx, timeout.as_millis() as c_int)
    }

    pub fn alert(&self, alert: AlertDescription) -> isize {
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
    pub const MAX_LEN: usize = 0x4000 + Self::PREFIIX_SIZE;
    pub const SUFFIX_SIZE: usize = 0x100;
    pub const BUF_SIZE: usize = Self::MAX_LEN + Self::SUFFIX_SIZE;

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
        if self.len() == Self::BUF_SIZE {
            self.finish_and_send();
            self.start();
        }
        self.buf[self.len] = value;
        self.len += 1;
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let diff = Self::MAX_LEN - self.len();

        if slice.len() <= diff {
            self.buf[self.len..][..slice.len()].copy_from_slice(slice);
            self.len += slice.len();
            return;
        }

        self.buf[self.len..].copy_from_slice(&slice[..diff]);
        self.len = Self::MAX_LEN;

        for chunk in slice[diff..].chunks(Self::MAX_LEN - Self::PREFIIX_SIZE) {
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

    /// Reads the contents of a single record into `buf`, returning an [`Err`] if the read failed,
    /// and an `Ok(len)` if the read was successful, where `len` is the number of bytes read.
    ///
    /// If less data is recieved than promised, it will return an `Err(ReadError::Timeout)` after
    /// `timeout` time.
    pub fn read_to(
        buf: &mut [u8; Self::BUF_SIZE],
        expected_type: ContentType,
        io: &Io,
        timeout: Duration,
    ) -> Result<usize, ReadError> {
        fn handle_alert(alert: &[u8; Alert::SIZE], io: &Io) -> AlertDescription {
            io.close();
            todo!()
        }

        let start = Instant::now();
        let mut header_buf = [0; Self::PREFIIX_SIZE];

        match io.poll(timeout) {
            ..0 => return Err(ReadError::IoError),
            0 => return Err(ReadError::Timeout),
            1.. => {},
        }

        io.read(&mut header_buf);

        let len = u16::from_be_bytes(
            header_buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..]
                .try_into()
                .unwrap(),
        ) as usize;

        if len > Self::MAX_LEN - Self::PREFIIX_SIZE {
            return Err(ReadError::RecordOverflow);
        }

        let msg_type = header_buf[0];

        if msg_type == ContentType::Alert.to_byte() {
            let mut alert = [0; Alert::SIZE];
            io.read(&mut alert);
            return Err(ReadError::RecievedAlert(handle_alert(&alert, io)));
        }

        if msg_type != expected_type.to_byte() {
            io.alert(AlertDescription::UnexpectedMessage);

            return Err(ReadError::UnexpectedMessage);
        }


        let mut bytes_read = 0;
        while bytes_read < len {
            // make sure we don't listen indefinetly
            let Some(remaining_time) = timeout.checked_sub(start.elapsed()) else {
                return Err(ReadError::Timeout);
            };

            match io.poll(remaining_time) {
                ..0 => return Err(ReadError::IoError),
                0 => return Err(ReadError::Timeout),
                1.. => {},
            }

            match io.read(&mut buf[bytes_read..]) {
                ..0 => return Err(ReadError::IoError),
                non_negative => bytes_read += non_negative as usize,
            }
        }
        Ok(len)
    }

    pub fn read(
        &mut self,
        expected_type: ContentType,
        timeout: Duration,
    ) -> Result<usize, ReadError> {
        Self::read_to(&mut self.buf, expected_type, &self.io, timeout)
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
