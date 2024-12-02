use std::mem::MaybeUninit;

use crate::{
    error::TlsError,
    record::{ContentType, ReadError, RecordLayer},
    Alert,
};

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

pub(crate) const SHAKE_LEN_SIZE: usize = 3;
pub(crate) const SHAKE_HEADER_SIZE: usize = size_of::<ShakeType>() + SHAKE_LEN_SIZE;

pub(crate) struct MsgBuf {
    max_len: usize,
    buf: Box<[u8]>,
    len: usize,
}

impl MsgBuf {
    const INIT_SIZE: usize = 0x4000;
    pub(crate) const LEN_SIZE: usize = 3;
    pub(crate) const HEADER_SIZE: usize = size_of::<ShakeType>() + Self::LEN_SIZE;
    pub(crate) fn new(max_len: usize) -> Self {
        let mut buf = Box::new_uninit_slice(Self::INIT_SIZE);
        buf.fill(MaybeUninit::zeroed());
        let buf = unsafe { buf.assume_init() };
        Self {
            max_len,
            buf,
            len: 0,
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.buf[Self::HEADER_SIZE..][..self.len]
    }

    pub(crate) fn read(&mut self, rl: &mut RecordLayer) -> Result<(), ReadError> {
        rl.fill(&mut self.buf[..Self::HEADER_SIZE])?;
        if rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
            rl.clear();
            rl.fill(&mut self.buf[..Self::HEADER_SIZE])?;
        }
        if rl.msg_type() != ContentType::Handshake.to_byte() {
            return Err(ReadError::Alert(TlsError::Sent(Alert::UnexpectedMessage)));
        }

        let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > self.max_len {
            return Err(ReadError::Alert(TlsError::Sent(Alert::HandshakeFailure)));
        }
        if len > self.buf.len() {
            todo!("resize buffer");
        }
        self.len = len;
        rl.fill(&mut self.buf[Self::HEADER_SIZE..][..len])
    }

    pub(crate) fn msg_type(&self) -> u8 {
        self.buf[0]
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}
