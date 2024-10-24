use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::ffi::c_void;
use crylib::aead;
use crate::aead::AeadWriter;
use crate::versions::LEGACY_PROTO_VERS;

#[repr(C)]
pub struct Io {
    write: extern "C" fn(*const c_void, usize, *const c_void) -> isize,
    read: extern "C" fn(*mut c_void, usize, *const c_void) -> isize,
    ctx: *const c_void,
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
    pub const LEN_SIZE: usize = 2;
    pub const PREFIIX_SIZE: usize = 5;
    pub const MAX_LEN: usize = 0x4000 + Self::PREFIIX_SIZE;
    pub const SUFFIX_SIZE: usize = 256;
    pub const BUF_SIZE: usize = Self::MAX_LEN + Self::SUFFIX_SIZE;

    pub fn init(record: &mut MaybeUninit<Self>, msg_type: ContentType, io: Io) -> &mut Self {
        // SAFETY: we initialize all of the fields
        let init_record = unsafe { &mut *(record as *mut MaybeUninit<Self> as *mut Self) };
        init_record.buf = [0; Self::BUF_SIZE];
        init_record.start_as(msg_type, io);
        init_record
    }

    pub fn start_as(&mut self, msg_type: ContentType, io: Io) {
        self.msg_type = msg_type;
        self.io = io;
        self.start();
    }

    pub fn start(&mut self) {
        self.buf[0] = self.msg_type.as_byte();
        self.buf[1..3].copy_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());
        self.len = Self::PREFIIX_SIZE;
    }

    pub fn finish(&mut self) {
        let len = ((self.len() - Self::PREFIIX_SIZE) as u16).to_be_bytes();
        self.buf[Self::PREFIIX_SIZE - Self::LEN_SIZE..][..Self::LEN_SIZE].copy_from_slice(&len);
        (self.io.write)(self.buf.as_ref() as *const [u8] as *const c_void, self.buf.len(), self.io.ctx);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, value: u8) {
        self.buf[self.len] = value;
        self.len += 1;
        if self.len() == Self::BUF_SIZE {
            self.finish();
            self.start();
        }
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let first_part = std::cmp::min(Self::BUF_SIZE - self.len(), slice.len());

        self.buf[self.len..first_part].copy_from_slice(&slice[..first_part]);
        self.len += first_part;
        if self.len() != Self::BUF_SIZE {
            return;
        }

        self.finish();
        self.start();

        let chunks = slice[first_part..].chunks_exact(Self::BUF_SIZE - Self::PREFIIX_SIZE);
        let remainder = chunks.remainder();

        for chunk in chunks {
            self.buf.copy_from_slice(chunk);
            self.finish();
            self.start();
        }
        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.len = remainder.len();
    }

    pub fn extend(&mut self, amt: usize) {
        self.extend_with(0, amt);
    }

    pub fn extend_with(&mut self, value: u8, amt: usize) {
        for _ in 0..amt {
            self.push(value);
        }
    }
}
