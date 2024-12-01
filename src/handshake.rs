use std::mem::MaybeUninit;

use crate::record::{ReadError, RecordLayer};

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
    buf: Box<[u8]>,
    msg_len: usize,
    pos: usize,
}

impl MsgBuf {
    const INIT_SIZE: usize = 0x4000;
    pub(crate) fn new() -> Self {
        let mut buf = Box::new_uninit_slice(Self::INIT_SIZE);
        buf.fill(MaybeUninit::zeroed());
        let buf = unsafe { buf.assume_init() };
        Self {
            buf,
            msg_len: 0,
            pos: 0,
        }
    }

    pub(crate) fn buf(&self) -> &[u8] {
        &self.buf[self.pos..self.msg_len]
    }

    pub(crate) fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.pos..self.msg_len]
    }

    pub(crate) fn read(&mut self, rl: &mut RecordLayer) -> Result<(), ReadError> {
        // TODO: make sure entire message is read and resize appropriately.
        self.msg_len = rl.read_to(&mut self.buf)?;
        self.pos = 0;
        Ok(())
    }

    pub(crate) fn advance(&mut self, amt: usize) {
        self.pos = std::cmp::min(self.pos + amt, self.msg_len);
    }

    pub(crate) fn msg_len(&self) -> usize {
        self.msg_len
    }
}

// use this for encrypted handshake messages
//pub(crate) fn read_encry_handshake<'a>(
//    buf: &'a mut [u8],
//    expected_type: ShakeType,
//    io: &Io,
//    timeout: Duration,
//) -> Result<&'a [u8], ShakeMsgParseError> {
//    assert!(
//        buf.len() >= RecordLayer::MAX_LEN + RecordLayer::SUFFIX_SIZE,
//        "buf must be able to fit at least one record"
//    );
//    let record_size = RecordLayer::read_to(
//        (&mut buf[..RecordLayer::MAX_LEN + RecordLayer::SUFFIX_SIZE])
//            .try_into()
//            .unwrap(),
//        ContentType::Handshake,
//        io,
//        timeout,
//    )?;
//    if buf[0] != expected_type.to_byte() {
//        io.alert(Alert::UnexpectedMessage);
//        return Err(ShakeMsgParseError::Failed);
//    }
//
//    let mut len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
//    while len > record_size - SHAKE_HEADER_SIZE
//        && buf.len() >= record_size + RecordLayer::MAX_LEN + RecordLayer::SUFFIX_SIZE
//    {
//        len += RecordLayer::read_to(
//            (&mut buf[record_size..][..RecordLayer::MAX_LEN + RecordLayer::SUFFIX_SIZE])
//                .try_into()
//                .unwrap(),
//            ContentType::Handshake,
//            io,
//            timeout,
//        )?;
//    }
//    todo!()
//}
//
//pub(crate) enum ShakeMsgParseError {
//    RecordError(ReadError),
//    Failed,
//}
//
//impl From<ReadError> for ShakeMsgParseError {
//    fn from(value: ReadError) -> Self {
//        Self::RecordError(value)
//    }
//}
