use std::mem::MaybeUninit;
use std::ops::ControlFlow;

use crate::aead::TlsAead;
use crate::alert::AlertMsg;
use crate::state::ProtShakeMsg;
use crate::Alert;
use crate::{
    client_hello::client_hello_client,
    config::Config,
    record::{ContentType, IoError, ReadError, RecordLayer},
    server_hello::server_hello_client,
    state::{GlobalState, MaybeProt, ShakeState, TranscriptHasher, UnprotShakeMsg},
    Error,
};

pub(crate) fn handshake_client(
    shake_state: &mut ShakeState,
    global_state: &mut GlobalState,
    config: &Config,
) -> Error {
    loop {
        match shake_state.state {
            MaybeProt::Unprot {
                ref mut next,
                ref mut unprot_state,
            } => match next {
                UnprotShakeMsg::ClientHello => {
                    match client_hello_client(unprot_state, &mut shake_state.buf, config) {
                        Error::None => (),
                        err => return err,
                    }
                    match shake_state
                        .buf
                        .write_raw(&mut global_state.rl, &mut global_state.transcript)
                    {
                        Ok(()) => (),
                        Err(IoError) => return Error::WantWrite,
                    }
                    *next = UnprotShakeMsg::ServerHello;
                },
                UnprotShakeMsg::ServerHello => {
                    match shake_state
                        .buf
                        .read_raw(&mut global_state.rl, &mut global_state.transcript)
                    {
                        Ok(()) => (),
                        Err(err) => return err.into(),
                    }
                    let aead = match server_hello_client(
                        shake_state.buf.data(),
                        unprot_state,
                        global_state,
                    ) {
                        Ok(aead) => aead,
                        Err(alert) => {
                            global_state.rl.close_raw(alert);
                            return Error::SentAlert(alert);
                        },
                    };
                    shake_state.state = MaybeProt::Prot {
                        next: ProtShakeMsg::EncryptedExtensions,
                        aead,
                    };
                },
            },
            MaybeProt::Prot {
                ref mut next,
                ref mut aead,
            } => match next {
                ProtShakeMsg::EncryptedExtensions => {
                    global_state.rl.peek(aead).unwrap();
                    if global_state.rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
                        global_state.rl.discard();
                        global_state.rl.peek(aead).unwrap();
                    }
                    println!("{}", global_state.rl.msg_type());
                    todo!("parse EncryptedExtensions");
                },
                _ => todo!("Finish handshake"),
            },
        };
    }
}

/// The message type of a handshake message.
#[derive(Debug, PartialEq, Eq)]
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
pub(crate) struct ShakeBuf {
    buf: Box<[u8]>,
    len: usize,
    /// The maximum size `buf` is allowed to be.
    max_size: usize,
    status: ReadStatus,
}

enum ReadStatus {
    NeedsHeader(usize),
    NeedsData(usize),
}

impl ReadStatus {
    const fn new() -> Self {
        Self::NeedsHeader(0)
    }
}

impl ShakeBuf {
    const INIT_SIZE: usize = 0x4000;
    pub(crate) const LEN_SIZE: usize = 3;
    pub(crate) const HEADER_SIZE: usize = size_of::<ShakeType>() + Self::LEN_SIZE;

    /// Constructs a new [`MsgBug`] with
    pub(crate) fn new(max_len: usize) -> Self {
        // TODO: use new_zeroed_slice or similar once stabilized.
        let mut buf = Box::new_uninit_slice(Self::INIT_SIZE);
        buf.fill(MaybeUninit::zeroed());
        Self {
            // SAFETY: a zeroed integer slice is valid.
            buf: unsafe { buf.assume_init() },
            len: 0,
            max_size: max_len,
            status: ReadStatus::new(),
        }
    }

    pub(crate) fn start(&mut self, msg_type: ShakeType) {
        self.len = 0;
        self.buf[0] = msg_type.to_byte();
        self.buf[1..][..Self::LEN_SIZE].copy_from_slice(&[0; Self::LEN_SIZE]);
    }

    pub(crate) fn push(&mut self, value: u8) {
        if self.len + Self::HEADER_SIZE + 1 > self.buf.len() {
            todo!()
        }
        self.buf[self.len + Self::HEADER_SIZE] = value;
        self.len += 1;
    }

    pub(crate) fn extend_from_slice(&mut self, slice: &[u8]) {
        if self.len + Self::HEADER_SIZE + slice.len() > self.buf.len() {
            todo!()
        }
        self.buf[Self::HEADER_SIZE + self.len..][..slice.len()].copy_from_slice(slice);
        self.len += slice.len();
    }

    /// Returns the data sent in the handshake message.
    ///
    /// This does NOT include the header.
    pub(crate) fn data(&self) -> &[u8] {
        &self.buf[Self::HEADER_SIZE..][..self.len]
    }

    /// Reads an entire plaintext handshake message.
    ///
    /// Despite its name, this is the handshake equivalent of [`RecordLayer::peek_raw`].
    pub(crate) fn read_raw(
        &mut self,
        rl: &mut RecordLayer,
        transcipt: &mut TranscriptHasher,
    ) -> Result<(), ReadError> {
        loop {
            match self.status {
                ReadStatus::NeedsHeader(ref mut amt) => {
                    if *amt == 0 {
                        rl.peek_raw()?;
                        if rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
                            rl.discard();
                            rl.peek_raw()?;
                        }
                        if rl.msg_type() == ContentType::Alert.to_byte() {
                            rl.read_remaining(&mut self.buf[Self::HEADER_SIZE..][..AlertMsg::SIZE]);
                            println!("{}", self.data()[1]);
                            todo!("handle alerts");
                        }
                        if rl.msg_type() != ContentType::Handshake.to_byte() {
                            return Err(ReadError::Alert(Alert::UnexpectedMessage));
                        }
                    }
                    while *amt < Self::HEADER_SIZE {
                        *amt += rl.read_raw(&mut self.buf[*amt..Self::HEADER_SIZE])?
                    }
                    self.len =
                        u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
                    if self.len > self.buf.len() {
                        todo!();
                    }
                    self.status = ReadStatus::NeedsData(0);
                },
                ReadStatus::NeedsData(ref mut amt) => {
                    while *amt < self.len {
                        *amt += rl.read_raw(
                            &mut self.buf[Self::HEADER_SIZE + *amt..Self::HEADER_SIZE + self.len],
                        )?
                    }
                    self.status = ReadStatus::new();
                    transcipt.update_with(&self.buf[..Self::HEADER_SIZE + self.len]);
                    return Ok(());
                },
            }
        }
    }

    pub(crate) fn write_raw(
        &mut self,
        rl: &mut RecordLayer,
        transcipt: &mut TranscriptHasher,
    ) -> Result<(), IoError> {
        self.encode_len();
        transcipt.update_with(&self.buf[..Self::HEADER_SIZE + self.len]);
        rl.write_raw(
            &self.buf[..Self::HEADER_SIZE + self.len],
            ContentType::Handshake,
        )
    }

    pub(crate) fn write(
        &mut self,
        rl: &mut RecordLayer,
        transcipt: &mut TranscriptHasher,
        aead: &mut TlsAead,
    ) -> Result<(), IoError> {
        self.encode_len();
        transcipt.update_with(&self.buf);
        rl.write(
            &self.buf[..Self::HEADER_SIZE + self.len],
            ContentType::Handshake,
            aead,
        )
    }

    /// Returns the type of handshake message the message is.
    ///
    /// A `u8` is returned instead of a [`ShakeType`] to avoid having to validate the type. As
    /// such, the returned value may not be a valid [`ShakeType`].
    pub(crate) fn msg_type(&self) -> u8 {
        self.buf[0]
    }

    pub(crate) fn encode_len(&mut self) {
        let len = (self.len as u32).to_be_bytes();
        self.buf[1..][..Self::LEN_SIZE].copy_from_slice(&len[1..]);
    }
}
