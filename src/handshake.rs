use std::mem::MaybeUninit;

use crate::{
    error::TlsError,
    record::{ContentType, ReadError, RecordLayer},
    Alert,
};

/// The message type of a handshake message.
#[expect(unused, reason = "not all handshake messages are implemented yet")]
#[repr(u8)]
pub(crate) enum ShakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl ShakeType {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Stores handshake messages for them to be parsed.
///
/// It can grow dynamically to adjust to larger sizes.
/// Currently, once it grows, it does not shrink. This may change.
///
/// This struct is only used for reading messages, not writing.
pub(crate) struct MsgBuf {
    buf: Box<[u8]>,
    /// The length of the handshake message.
    ///
    /// This does NOT include the header.
    len: usize,
    /// The maximum size `buf` is allowed to be.
    max_size: usize,
}

impl MsgBuf {
    const INIT_SIZE: usize = 0x4000;
    pub(crate) const LEN_SIZE: usize = 3;
    pub(crate) const HEADER_SIZE: usize = size_of::<ShakeType>() + Self::LEN_SIZE;

    /// Constructs a new [`MsgBug`] with
    pub(crate) fn new(max_len: usize) -> Self {
        // TODO: use new_zeroed_slice or similar once stabilized.
        let mut buf = Box::new_uninit_slice(Self::INIT_SIZE);
        buf.fill(MaybeUninit::zeroed());
        let buf = unsafe { buf.assume_init() };
        Self {
            buf,
            len: 0,
            max_size: max_len,
        }
    }

    /// Returns the data sent in the handshake message.
    ///
    /// This does NOT include the header.
    pub(crate) fn data(&self) -> &[u8] {
        &self.buf[Self::HEADER_SIZE..][..self.len]
    }

    pub(crate) fn read(&mut self, rl: &mut RecordLayer) -> Result<(), ReadError> {
        fn fill(rl: &mut RecordLayer, buf: &[u8]) -> Result<(), ReadError> {
            todo!()
        }
        fill(rl, &mut self.buf[..Self::HEADER_SIZE])?;
        if rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
            rl.clear();
            fill(rl, &mut self.buf[..Self::HEADER_SIZE])?;
        }
        if rl.msg_type() != ContentType::Handshake.to_byte() {
            return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
        }
        let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > self.max_size {
            println!("{len}");
            return Err(ReadError::Alert(TlsError::Sent(Alert::HandshakeFailure)));
        }
        if len > self.buf.len() {
            todo!("resize buffer");
        }
        self.len = len;
        fill(rl, &mut self.buf[Self::HEADER_SIZE..][..len])
    }

    /// Returns the type of handshake message the message is.
    ///
    /// A `u8` is returned instead of a [`ShakeType`] to avoid having to validate the type. As
    /// such, the returned value may not be a valid [`ShakeType`].
    pub(crate) fn msg_type(&self) -> u8 {
        self.buf[0]
    }

    /// The length of the handshake message.
    ///
    /// This does not include the header.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}
