use crylib::hash::{BufHasher, Hasher, Sha256};

use crate::aead::TlsAead;
use crate::config::Config;
use crate::extensions::key_share::{GroupKeys, KeyGenError};
use crate::handshake::ShakeBuf;
use crate::record::{Io, RecordLayer};
use crate::CipherList;
/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection {
    pub(crate) state: TlsStatus,
    pub(crate) gloabl_state: GlobalState,
    pub(crate) config: Config,
}

impl Connection {
    pub(crate) fn new(io: Io) -> Box<Self> {
        Box::new(Self {
            state: TlsStatus::None,
            gloabl_state: GlobalState {
                rl: RecordLayer::new(io),
                secret: [0; Sha256::HASH_SIZE],
                transcript: TranscriptHasher::new(),
                app_proto: [0; 256],
            },
            config: Config::default(),
        })
    }
}

pub(crate) struct GlobalState {
    pub(crate) rl: RecordLayer,
    pub(crate) secret: [u8; Sha256::HASH_SIZE],
    pub(crate) transcript: TranscriptHasher,
    pub(crate) app_proto: [u8; 256],
}

pub(crate) struct ExtState {
    pub(crate) app_proto: [u8; 256],
}

pub(crate) enum TlsStatus {
    None,
    Shake(ShakeState),
    App { aead: TlsAead },
}

pub(crate) struct UnprotShakeState {
    pub(crate) priv_keys: GroupKeys,
    pub(crate) sup_groups: u16,
    pub(crate) sig_algs: u16,
    pub(crate) ciphers: CipherList,
}

pub(crate) enum MaybeProt {
    Unprot {
        next: UnprotShakeMsg,
        state: UnprotShakeState,
    },
    Prot {
        next: ProtShakeMsg,
        state: TlsAead,
    },
}

#[derive(PartialEq, Eq)]
pub(crate) enum UnprotShakeMsg {
    ClientHello,
    ServerHello,
}

pub(crate) enum ProtShakeMsg {
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    KeyUpdate,
    MessageHash,
}

pub(crate) struct ShakeState {
    pub(crate) state: MaybeProt,
    pub(crate) buf: ShakeBuf,
}

impl ShakeState {
    pub(crate) fn new(config: &Config) -> Result<Self, KeyGenError> {
        todo!()
    }
}

pub(crate) type TranscriptHasher = BufHasher<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>;
