mod encrypt;
mod raw;

use crylib::hash::{BufHasher, Sha256};

use crate::error::TlsError;
pub(crate) use encrypt::{EncReadError, EncryptedRecLayer};
pub use raw::Io;

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
    /// The number of bytes in the buffer *including* the header.
    len: usize,
    msg_type: ContentType,
    io: Io,
    transcript: BufHasher<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>,
}

#[derive(Debug)]
pub(crate) enum ReadError {
    IoError,
    Alert(TlsError),
    Timeout,
}
