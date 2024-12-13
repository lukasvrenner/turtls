use crylib::hash::{BufHasher, Hasher, Sha256};

use crate::aead::TlsAead;
use crate::config::TurtlsConfig;
use crate::extensions::key_share::{GroupKeys, KeyGenError};
use crate::handshake::ShakeBuf;
use crate::record::{TurtlsIo, RecordLayer};
use crate::{TurtlsAlert, TurtlsCipherList};
/// A TLS connection object.
///
/// This object may be reused between multiple consecutive connections.
pub struct TurtlsConn {
    pub(crate) state: TlsStatus,
    pub(crate) gloabl_state: GlobalState,
    pub(crate) config: TurtlsConfig,
}

impl TurtlsConn {
    pub(crate) fn new(io: TurtlsIo) -> Box<Self> {
        Box::new(Self {
            state: TlsStatus::None,
            gloabl_state: GlobalState {
                tls_error: TurtlsAlert::CloseNotify,
                rl: RecordLayer::new(io),
                secret: [0; Sha256::HASH_SIZE],
                transcript: TranscriptHasher::new(),
                app_proto: [0; 256],
            },
            config: TurtlsConfig::default(),
        })
    }
}

pub(crate) struct GlobalState {
    pub(crate) tls_error: TurtlsAlert,
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
    #[expect(unused, reason = "Application data is not yet supported")]
    App {
        aead: TlsAead,
    },
}

pub(crate) struct UnprotShakeState {
    pub(crate) priv_keys: GroupKeys,
    pub(crate) sup_groups: u16,
    #[expect(unused, reason = "Certificates are not yet supported")]
    pub(crate) sig_algs: u16,
    pub(crate) ciphers: TurtlsCipherList,
}

pub(crate) enum MaybeProt {
    Unprot {
        next: UnprotShakeMsg,
        unprot_state: UnprotShakeState,
    },
    Prot {
        next: ProtShakeMsg,
        aead: TlsAead,
    },
}

#[derive(PartialEq, Eq)]
pub(crate) enum UnprotShakeMsg {
    ClientHello,
    ServerHello,
}

#[expect(unused, reason = "Not all protected messages are supported yet")]
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
    pub(crate) fn new(config: &TurtlsConfig) -> Result<Self, KeyGenError> {
        Ok(Self {
            state: MaybeProt::Unprot {
                next: UnprotShakeMsg::ClientHello,
                unprot_state: UnprotShakeState {
                    priv_keys: GroupKeys::generate(config.extensions.sup_groups)?,
                    sup_groups: config.extensions.sup_groups,
                    sig_algs: config.extensions.sig_algs,
                    ciphers: config.cipher_suites,
                },
            },
            buf: ShakeBuf::new(0x20000),
        })
    }
}

pub(crate) type TranscriptHasher = BufHasher<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }, Sha256>;
