use crate::aead::AeadWriter;
use crate::alert::{Alert, AlertDescription};
use crate::versions::LEGACY_PROTO_VERS;
use crylib::aead;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

#[repr(C)]
pub struct Io {
    pub write: extern "C" fn(buf: *const c_void, amt: usize, ctx: *const c_void) -> isize,
    pub read: extern "C" fn(buf: *mut c_void, amt: usize, ctx: *const c_void) -> isize,
    pub is_ready: extern "C" fn(ctx: *const c_void) -> bool,
    pub close: extern "C" fn(ctx: *const c_void),
    pub ctx: *const c_void,
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
    pub fn as_byte(self) -> u8 {
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
        let init_record;
        // SAFETY: we initialize all of the fields
        unsafe {
            init_record = &mut *(record as *mut MaybeUninit<Self> as *mut Self);
            init_record.buf = [0; Self::BUF_SIZE];
            init_record.io = io;
            init_record.start_as(msg_type);
        }
        init_record
    }

    pub fn start_as(&mut self, msg_type: ContentType) {
        self.msg_type = msg_type;
        self.start();
    }

    pub fn start(&mut self) {
        self.buf[0] = self.msg_type.as_byte();
        self.buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        self.len = Self::PREFIIX_SIZE;
    }

    pub fn finish(&mut self) {
        let len = ((self.len() - Self::PREFIIX_SIZE) as u16).to_be_bytes();
        self.buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..Self::PREFIIX_SIZE].copy_from_slice(&len);
    }

    pub fn finish_and_send(&mut self) {
        self.finish();
        (self.io.write)(
            self.buf.as_ref() as *const [u8] as *const c_void,
            self.buf.len(),
            self.io.ctx,
        );
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, value: u8) {
        self.buf[self.len] = value;
        self.len += 1;
        if self.len() == Self::BUF_SIZE {
            self.finish_and_send();
            self.start();
        }
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
    pub fn read(
        buf: &mut [u8; Self::BUF_SIZE],
        expected_type: ContentType,
        io: &Io,
        timeout: Duration,
    ) -> Result<usize, ReadError> {
        fn handle_alert(alert: &[u8; Alert::SIZE], io: &Io) -> AlertDescription {
            (io.close)(io.ctx);
            todo!()
        }

        let mut header_buf = [0; Self::PREFIIX_SIZE];
        (io.read)(
            &mut header_buf as *mut [u8] as *mut c_void,
            Self::PREFIIX_SIZE,
            io.ctx,
        );

        let len = u16::from_be_bytes(
            header_buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..]
                .try_into()
                .unwrap(),
        ) as usize;

        if len > Self::MAX_LEN - Self::PREFIIX_SIZE {
            return Err(ReadError::RecordOverflow);
        }

        let msg_type = header_buf[0];

        if msg_type == ContentType::Alert.as_byte() {
            let mut alert = [0; Alert::SIZE];
            (io.read)(&mut alert as *mut [u8] as *mut c_void, Alert::SIZE, io.ctx);
            return Err(ReadError::RecievedAlert(handle_alert(&alert, io)));
        }

        if msg_type != expected_type.as_byte() {
            let mut alert = [0; Self::PREFIIX_SIZE + Alert::SIZE];

            alert[0] = ContentType::Alert.as_byte();
            alert[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
            alert[Self::PREFIIX_SIZE - Self::LEN_SIZE..Self::PREFIIX_SIZE]
                .copy_from_slice(&(Alert::SIZE as u16).to_be_bytes());

            Alert::new_in(
                (&mut alert[Self::PREFIIX_SIZE..]).try_into().unwrap(),
                AlertDescription::UnexpectedMessage,
            );

            (io.write)(&alert as *const [u8] as *const c_void, alert.len(), io.ctx);
            (io.close)(io.ctx);

            return Err(ReadError::UnexpectedMessage);
        }

        let start = Instant::now();

        // make sure we don't listen indefinetly
        let mut bytes_remaining = len;
        while bytes_remaining > 0 {
            if start.elapsed() > timeout {
                return Err(ReadError::Timeout);
            }
            if (io.is_ready)(io.ctx) {
                let Ok(bytes_read): Result<usize, _> =
                    (io.read)(buf as *mut [u8] as *mut c_void, bytes_remaining, io.ctx).try_into()
                else {
                    return Err(ReadError::IoError);
                };

                // io.read should theoretically never return more than bytes_remaining, but it's better
                // to be safe than sorry
                bytes_remaining = bytes_remaining.saturating_sub(bytes_read);
            }
        }
        return Ok(len);
    }
}

pub enum ReadError {
    RecordOverflow,
    IoError,
    RecievedAlert(AlertDescription),
    UnexpectedMessage,
    Timeout,
}
