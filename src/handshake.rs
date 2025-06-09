use std::mem::MaybeUninit;

use crate::aead::TlsAead;
use crate::client_hello::client_hello_client;
use crate::config::TurtlsConfig;
use crate::error::{FullError, TurtlsError};
use crate::extensions::parse_encrypted_extensions;
use crate::record::{ContentType, RecordLayer};
use crate::server_hello::server_hello_client;
use crate::state::{
    GlobalState, MaybeProt, ProtShakeMsg, ShakeState, TranscriptHasher, UnprotShakeMsg,
};
use crate::TurtlsAlert;

/// Performs the TLS 1.3 handshake as the client.
///
/// Alerts are handled and sent in this function. Do not send alerts on higher levels.
pub(crate) fn handshake_client(
    shake_state: &mut ShakeState,
    global_state: &mut GlobalState,
    config: &TurtlsConfig,
) -> Result<(), ()> {
    // This would be so much cleaner with C-style switch statement :)
    loop {
        match shake_state.state {
            MaybeProt::Unprot {
                ref mut next,
                ref mut unprot_state,
            } => match next {
                UnprotShakeMsg::ClientHello => {
                    // Don't send alert because handshake hasn't started.
                    client_hello_client(unprot_state, &mut shake_state.buf, config)
                        .map_err(|err| global_state.error.turtls_error = err)?;

                    shake_state
                        .buf
                        .write_raw(&mut global_state.rl, &mut global_state.transcript)
                        .map_err(|err| global_state.error.turtls_error = err)?;

                    *next = UnprotShakeMsg::ServerHello;
                },
                UnprotShakeMsg::ServerHello => {
                    shake_state
                        .buf
                        .read_raw(&mut global_state.rl, &mut global_state.transcript)
                        .map_err(|err| {
                            if let TurtlsError::Tls = err.turtls_error {
                                global_state.rl.close_raw(err.alert);
                            }
                            global_state.error = err
                        })?;
                    let aead =
                        server_hello_client(shake_state.buf.data(), unprot_state, global_state)
                            .map_err(|alert| {
                                global_state.rl.close_raw(alert);
                                global_state.error = FullError::sending_alert(alert);
                            })?;
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
                    shake_state
                        .buf
                        .read(&mut global_state.rl, aead, &mut global_state.transcript)
                        .map_err(|err| {
                            if let TurtlsError::Tls = err.turtls_error {
                                global_state.rl.close(err.alert, aead);
                            }
                            global_state.error = err
                        })?;
                    parse_encrypted_extensions(shake_state.buf.data(), global_state).map_err(
                        |alert| {
                            global_state.rl.close(alert, aead);
                            global_state.error = FullError::sending_alert(alert);
                        },
                    )?;
                    *next = ProtShakeMsg::Certificate;
                },
                ProtShakeMsg::Certificate => {
                    shake_state
                        .buf
                        .read(&mut global_state.rl, aead, &mut global_state.transcript)
                        .map_err(|err| {
                            if let TurtlsError::Tls = err.turtls_error {
                                global_state.rl.close(err.alert, aead);
                            }
                            global_state.error = err
                        })?;
                    let cert_msg = shake_state.buf.data();

                    let context_len = cert_msg[0] as usize;
                    let certs = &cert_msg[1 + context_len as usize..];

                    let data_len = u32::from_be_bytes([0, certs[0], certs[1], certs[2]]) as usize;
                    let count = crate::certificates::CertIter::new(&certs[3..][..data_len])
                        .count();

                    println!("number of certificates: {count}");
                    todo!("validate certificate");
                },
                _ => todo!("Finish handshake"),
            },
        };
    }
}

/// The message type of a handshake message.
#[derive(Debug, PartialEq, Eq)]
#[expect(unused, reason = "not all handshake messages are implemented yet")]
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
pub(crate) struct ShakeBuf {
    buf: Box<[u8]>,
    /// The length of the message excluding the header.
    len: usize,
    /// The maximum size `buf` is allowed to be.
    max_size: usize,
    status: ReadStatus,
}

enum ReadStatus {
    /// The message header has not been completely read yet.
    ///
    /// The internal value represents the number of header bytes already read.
    NeedsHeader(usize),
    /// The message data has not be completely read yet.
    ///
    /// The internal value represents the number of data bytes already read.
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
            todo!("grow handshake buffer");
        }
        self.buf[self.len + Self::HEADER_SIZE] = value;
        self.len += 1;
    }

    pub(crate) fn extend_from_slice(&mut self, slice: &[u8]) {
        if self.len + Self::HEADER_SIZE + slice.len() > self.buf.len() {
            todo!("grow handshake buffer");
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

    fn read_inner(
        &mut self,
        rl: &mut RecordLayer,
        mut get_fn: impl FnMut(&mut RecordLayer) -> Result<(), FullError>,
        transcript: &mut TranscriptHasher,
    ) -> Result<(), FullError> {
        loop {
            match self.status {
                ReadStatus::NeedsHeader(ref mut amt) => {
                    if *amt == 0 {
                        get_fn(rl)?;
                        if rl.msg_type() == ContentType::ChangeCipherSpec.to_byte() {
                            rl.discard();
                            get_fn(rl)?;
                        }
                        rl.check_alert()
                            .map_err(|alert| FullError::recving_alert(alert))?;
                        if rl.msg_type() != ContentType::Handshake.to_byte() {
                            return Err(FullError::sending_alert(TurtlsAlert::UnexpectedMessage));
                        }
                    }
                    while *amt < Self::HEADER_SIZE {
                        get_fn(rl)?;
                        let new_bytes = rl.read_remaining(&mut self.buf[*amt..Self::HEADER_SIZE]);
                        if new_bytes == 0 {
                            return Err(FullError::sending_alert(TurtlsAlert::IllegalParam));
                        }
                        *amt += new_bytes;
                    }
                    self.len =
                        u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
                    if self.len > self.buf.len() {
                        todo!("grow handshake buffer");
                    }
                    self.status = ReadStatus::NeedsData(0);
                },
                ReadStatus::NeedsData(ref mut amt) => {
                    while *amt < self.len {
                        get_fn(rl)?;
                        let new_bytes = rl.read_remaining(
                            &mut self.buf[Self::HEADER_SIZE + *amt..Self::HEADER_SIZE + self.len],
                        );
                        if new_bytes == 0 {
                            return Err(FullError::sending_alert(TurtlsAlert::IllegalParam));
                        }
                        *amt += new_bytes;
                    }
                    self.status = ReadStatus::new();
                    transcript.update_with(&self.buf[..Self::HEADER_SIZE + self.len]);
                    return Ok(());
                },
            }
        }
    }

    /// Reads an entire plaintext handshake message.
    pub(crate) fn read_raw(
        &mut self,
        rl: &mut RecordLayer,
        transcript: &mut TranscriptHasher,
    ) -> Result<(), FullError> {
        let get_fn = RecordLayer::get_raw;
        self.read_inner(rl, get_fn, transcript)
    }

    pub(crate) fn read(
        &mut self,
        rl: &mut RecordLayer,
        aead: &mut TlsAead,
        transcript: &mut TranscriptHasher,
    ) -> Result<(), FullError> {
        let get_fn = |rl: &mut RecordLayer| RecordLayer::get(rl, aead);
        self.read_inner(rl, get_fn, transcript)
    }

    pub(crate) fn write_raw(
        &mut self,
        rl: &mut RecordLayer,
        transcript: &mut TranscriptHasher,
    ) -> Result<(), TurtlsError> {
        self.encode_len();

        transcript.update_with(&self.buf[..Self::HEADER_SIZE + self.len]);
        rl.write_raw(
            &self.buf[..Self::HEADER_SIZE + self.len],
            ContentType::Handshake,
        )
    }

    pub(crate) fn write(
        &mut self,
        rl: &mut RecordLayer,
        transcript: &mut TranscriptHasher,
        aead: &mut TlsAead,
    ) -> Result<(), TurtlsError> {
        self.encode_len();
        transcript.update_with(&self.buf);
        rl.write(
            &self.buf[..Self::HEADER_SIZE + self.len],
            ContentType::Handshake,
            aead,
        )
    }

    /// Returns the type of handshake message the message is.
    ///
    /// A `u8` is returned instead of a [`ShakeType`] to avoid having to validate the type. The
    /// returned type may not be a valid [`ShakeType`].
    pub(crate) fn msg_type(&self) -> u8 {
        self.buf[0]
    }

    pub(crate) fn encode_len(&mut self) {
        let len = (self.len as u32).to_be_bytes();
        self.buf[1..][..Self::LEN_SIZE].copy_from_slice(&len[1..]);
    }
}
