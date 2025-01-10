use crylib::aead::TAG_SIZE;

use std::ffi::c_void;

mod read;
mod write;

use read::ReadBuf;
use write::WriteBuf;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub(crate) const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// The functions to use to perform IO.
///
/// This includes reading, writing, and closing the connection.
#[repr(C)]
pub struct TurtlsIo {
    /// A write function.
    ///
    /// `write_fn` must return the number of bytes written. To indicate an error, it must return a
    /// value less than `1`.
    ///
    /// `buf`: the buffer to write.
    /// `amt`: the number of bytes to write.
    /// `ctx`: contextual data.
    pub write_fn: extern "C" fn(buf: *const c_void, amt: usize, ctx: *const c_void) -> isize,
    /// A read function.
    ///
    /// `read_fn` must return the number of bytes read. To indicate an error, it must return a
    /// value less than `1`.
    ///
    /// `buf`: the buffer to read to.
    /// `amt`: the maximum number of bytes to read.
    /// `ctx`: contextual data.
    pub read_fn: extern "C" fn(buf: *mut c_void, amt: usize, ctx: *const c_void) -> isize,

    /// A function to close the connection.
    ///
    /// `ctx`: contextual data.
    pub close_fn: extern "C" fn(ctx: *const c_void),

    /// Contextual data.
    ///
    /// This can simply be a file descriptor, or it can be something more complex. For example, it
    /// could store both a read and a write file descriptor, error values, and even mutable state.
    ///
    /// Lifetime: this pointer must be valid for the duration of the connection.
    pub ctx: *mut c_void,
}

impl TurtlsIo {
    #[must_use]
    fn read(&self, buf: &mut [u8]) -> Option<usize> {
        let result = (self.read_fn)(buf as *mut _ as *mut c_void, buf.len(), self.ctx);
        if result <= 0 {
            return None;
        }
        return Some(result as usize);
    }

    #[must_use]
    fn write(&self, buf: &[u8]) -> Option<usize> {
        let result = (self.write_fn)(buf as *const _ as *const c_void, buf.len(), self.ctx);
        if result <= 0 {
            return None;
        }
        return Some(result as usize);
    }

    /// Closes the connection
    fn close(&self) {
        (self.close_fn)(self.ctx);
    }
}

pub(crate) struct RecordLayer {
    rbuf: ReadBuf,
    wbuf: WriteBuf,
    io: TurtlsIo,
}

impl RecordLayer {
    pub(crate) const LEN_SIZE: usize = 0x2;
    pub(crate) const HEADER_SIZE: usize = 0x5;
    pub(crate) const MAX_LEN: usize = 0x4000;
    pub(crate) const SUFFIX_SIZE: usize = 0x100;
    pub(crate) const BUF_SIZE: usize = Self::HEADER_SIZE + Self::MAX_LEN + Self::SUFFIX_SIZE;

    pub(crate) const MIN_PROT_LEN: usize = TAG_SIZE + size_of::<ContentType>();

    pub(crate) const fn new(io: TurtlsIo) -> Self {
        Self {
            rbuf: ReadBuf::new(),
            wbuf: WriteBuf::new(),
            io,
        }
    }
}
