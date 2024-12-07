use crate::aead::TlsAead;
use crate::state::ProtShakeMsg;
use crate::{
    client_hello::client_hello_client,
    config::Config,
    record::{ContentType, IoError, ReadError, RecordLayer},
    server_hello::server_hello_client,
    state::{GlobalState, MaybeProt, ShakeState, TranscriptHasher, UnprotShakeMsg},
    ShakeResult,
};

pub(crate) fn handshake_client(
    shake_state: &mut ShakeState,
    global_state: &mut GlobalState,
    config: &Config,
) -> ShakeResult {
    loop {
        match shake_state.state {
            MaybeProt::Unprot {
                ref mut next,
                ref mut state,
            } if next == &mut UnprotShakeMsg::ClientHello => {
                client_hello_client(state, &mut shake_state.buf, config);
                shake_state
                    .buf
                    .write_raw(&mut global_state.rl, &mut global_state.transcript);
                *next = UnprotShakeMsg::ServerHello;
            },
            MaybeProt::Unprot {
                ref mut next,
                ref mut state,
            } if next == &mut UnprotShakeMsg::ServerHello => {
                shake_state.buf.read_raw(&mut global_state.rl);
                let aead = match server_hello_client(shake_state.buf.data(), state, global_state) {
                    Ok(aead) => aead,
                    Err(err) => todo!(),
                };
                shake_state.state = MaybeProt::Prot {
                    next: ProtShakeMsg::EncryptedExtensions,
                    state: aead,
                };
                todo!()
            },
            _ => todo!(),
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
    buf: Vec<u8>,
    /// The maximum size `buf` is allowed to be.
    max_size: usize,
}

impl ShakeBuf {
    const INIT_SIZE: usize = 0x4000;
    pub(crate) const LEN_SIZE: usize = 3;
    pub(crate) const HEADER_SIZE: usize = size_of::<ShakeType>() + Self::LEN_SIZE;

    /// Constructs a new [`MsgBug`] with
    pub(crate) fn new(max_len: usize) -> Self {
        // TODO: use new_zeroed_slice or similar once stabilized.
        Self {
            buf: Vec::with_capacity(Self::INIT_SIZE),
            max_size: max_len,
        }
    }

    pub(crate) fn start(&mut self, msg_type: ShakeType) {
        self.buf.clear();
        self.buf.push(msg_type.to_byte());
        self.buf.extend_from_slice(&[0; Self::LEN_SIZE]);
    }

    /// Returns the data sent in the handshake message.
    ///
    /// This does NOT include the header.
    pub(crate) fn data(&self) -> &[u8] {
        &self.buf[Self::HEADER_SIZE..]
    }

    pub(crate) fn read_raw(&mut self, rl: &mut RecordLayer) -> Result<(), ReadError> {
        todo!()
    }

    pub(crate) fn write_raw(
        &mut self,
        rl: &mut RecordLayer,
        transcipt: &mut TranscriptHasher,
    ) -> Result<(), IoError> {
        self.encode_len();
        transcipt.update_with(&self.buf);
        rl.write_raw(&self.buf, ContentType::Handshake)
    }

    pub(crate) fn write(
        &mut self,
        rl: &mut RecordLayer,
        transcipt: &mut TranscriptHasher,
        aead: &mut TlsAead,
    ) -> Result<(), IoError> {
        self.encode_len();
        transcipt.update_with(&self.buf);
        rl.write(&self.buf, ContentType::Handshake, aead)
    }

    pub(crate) fn push(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub(crate) fn extend_from_slice(&mut self, slice: &[u8]) {
        self.buf.extend_from_slice(slice);
    }

    /// Returns the type of handshake message the message is.
    ///
    /// A `u8` is returned instead of a [`ShakeType`] to avoid having to validate the type. As
    /// such, the returned value may not be a valid [`ShakeType`].
    pub(crate) fn msg_type(&self) -> u8 {
        self.buf[0]
    }

    pub(crate) fn encode_len(&mut self) {
        let len = ((self.buf.len() - Self::HEADER_SIZE) as u32).to_be_bytes();
        self.buf[1..][..Self::LEN_SIZE].copy_from_slice(&len[..Self::LEN_SIZE]);
    }
}
