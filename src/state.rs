use crylib::hash::Sha256;

use crate::config::Config;
use crate::extensions::key_share::{GroupKeys, KeyGenError};
use crate::handshake::{ShakeBuf, ShakeType};
use crate::record::{Io, RecordLayer};
use crate::CipherList;
/// A TLS connection buffer.
///
/// This connection buffer may be reused between multiple consecutive connections.
pub struct Connection {
    pub(crate) status: TlsStatus,
    pub(crate) state: State,
    pub(crate) config: Config,
}

impl Connection {
    pub(crate) fn new(io: Io) -> Box<Self> {
        Box::new(Self {
            status: TlsStatus::None,
            state: State {
                rl: RecordLayer::new(io),
                secret: [0; Sha256::HASH_SIZE],
                app_proto: [0; 256],
            },
            config: Config::default(),
        })
    }
}

pub(crate) struct State {
    pub(crate) rl: RecordLayer,
    pub(crate) secret: [u8; Sha256::HASH_SIZE],
    pub(crate) app_proto: [u8; 256],
}

pub(crate) struct ExtState {
    pub(crate) app_proto: [u8; 256],
}

pub(crate) enum TlsStatus {
    None,
    Shake(ShakeState),
    App,
}

pub(crate) struct ShakeState {
    pub(crate) next: ShakeType,
    pub(crate) buf: ShakeBuf,
    pub(crate) crypto: ShakeCrypto,
}

pub(crate) struct ShakeCrypto {
    pub(crate) priv_keys: GroupKeys,
    pub(crate) sup_groups: u16,
    pub(crate) sig_algs: u16,
    pub(crate) ciphers: CipherList,
}

impl ShakeState {
    pub(crate) fn new(config: &Config) -> Result<Self, KeyGenError> {
        Ok(Self {
            next: ShakeType::ClientHello,
            buf: ShakeBuf::new(0x4000),
            crypto: ShakeCrypto {
                priv_keys: GroupKeys::generate(config.extensions.sup_groups)?,
                sig_algs: config.extensions.sig_algs,
                sup_groups: config.extensions.sup_groups,
                ciphers: config.cipher_suites,
            },
        })
    }
}
