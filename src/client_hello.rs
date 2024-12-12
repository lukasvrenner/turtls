use crate::cipher_suites::CipherList;
use crate::config::Config;
use crate::extensions::versions::{ProtocolVersion, LEGACY_PROTO_VERS};
use crate::extensions::ExtList;
use crate::handshake::{ShakeBuf, ShakeType};
use crate::state::UnprotShakeState;
use crate::Error;
use getrandom::getrandom;

pub(crate) const RANDOM_BYTES_LEN: usize = 32;
pub(crate) const LEGACY_SESSION_ID: u8 = 0;
pub(crate) const LEGACY_COMPRESSION_METHODS: [u8; 2] = [1, 0];

pub(crate) fn client_hello_client(
    unprot_state: &mut UnprotShakeState,
    shake_buf: &mut ShakeBuf,
    config: &Config,
) -> Error {
    shake_buf.start(ShakeType::ClientHello);

    shake_buf.extend_from_slice(&LEGACY_PROTO_VERS.to_be_bytes());

    let mut random_bytes = [0; RANDOM_BYTES_LEN];
    if let Err(_) = getrandom(&mut random_bytes) {
        return Error::RngError;
    }
    shake_buf.extend_from_slice(&random_bytes);

    shake_buf.push(LEGACY_SESSION_ID);

    let len = (config.cipher_suites.len() as u16).to_be_bytes();
    shake_buf.extend_from_slice(&len);

    config.cipher_suites.write_to(shake_buf);

    shake_buf.extend_from_slice(&LEGACY_COMPRESSION_METHODS);

    let len = (config.extensions.len_client() as u16).to_be_bytes();
    shake_buf.extend_from_slice(&len);
    config
        .extensions
        .write_client(shake_buf, &unprot_state.priv_keys);
    Error::None
}

fn cli_hel_len(config: &Config) -> usize {
    size_of::<ProtocolVersion>()
        + RANDOM_BYTES_LEN
        // TODO use size_of_val once it is const-stabilized
        + size_of_val(&LEGACY_SESSION_ID)
        + CipherList::LEN_SIZE
        + config.cipher_suites.len()
        // TODO use size_of_val once it is const-stabilized
        + size_of_val(&LEGACY_COMPRESSION_METHODS)
        + ExtList::LEN_SIZE
        + config.extensions.len_client()
}
//pub(crate) struct ClientHello {
//    pub(crate) cipher_suites: CipherList,
//    pub(crate) extensions: ExtList,
//}
//
//
//impl ClientHello {
//    pub(crate) fn len(&self) -> usize {
//        size_of::<ProtocolVersion>()
//            + Self::RANDOM_BYTES_LEN
//            // TODO use size_of_val once it is const-stabilized
//            + size_of_val(&Self::LEGACY_SESSION_ID)
//            + CipherList::LEN_SIZE
//            + self.cipher_suites.len()
//            // TODO use size_of_val once it is const-stabilized
//            + size_of_val(&Self::LEGACY_COMPRESSION_METHODS)
//            + ExtList::LEN_SIZE
//            + self.extensions.len_client()
//    }
//
//    pub(crate) fn write_to(
//        &self,
//        rl: &mut RecordLayer,
//        keys: &GroupKeys,
//    ) -> Result<(), CliHelError> {
//        rl.start_as(ContentType::Handshake);
//        rl.push(ShakeType::ClientHello.to_byte())?;
//
//        let len = self.len() as u32;
//        rl.push_u24(len)?;
//
//        rl.push_u16(LEGACY_PROTO_VERS.as_int())?;
//
//        let mut random_bytes = [0; Self::RANDOM_BYTES_LEN];
//        getrandom(&mut random_bytes)?;
//        rl.extend_from_slice(&random_bytes)?;
//
//        rl.push(Self::LEGACY_SESSION_ID)?;
//
//        let len = self.cipher_suites.len() as u16;
//        rl.push_u16(len)?;
//        self.cipher_suites.write_to(rl)?;
//
//        rl.extend_from_slice(&Self::LEGACY_COMPRESSION_METHODS)?;
//
//        let len = self.extensions.len_client() as u16;
//        rl.push_u16(len)?;
//        self.extensions.write_client(rl, keys)?;
//
//        rl.finish().map_err(|err| err.into())
//    }
//}
//
//pub(crate) enum CliHelError {
//    RngError,
//    IoError(IoError),
//}
//
//impl From<Error> for CliHelError {
//    fn from(_: Error) -> Self {
//        Self::RngError
//    }
//}
//
//impl From<IoError> for CliHelError {
//    fn from(value: IoError) -> Self {
//        Self::IoError(value)
//    }
//}
//
//pub(crate) enum CliHelloParseError {
//    MissingData,
//    InvalidLengthEncoding,
//}
//
//pub(crate) struct ClientHelloRef<'a> {
//    pub(crate) random_bytes: &'a [u8; 32],
//    pub(crate) session_id: &'a [u8],
//    pub(crate) cipher_suites: &'a [u8],
//    pub(crate) extensions: &'a [u8],
//}
//
//impl<'a> ClientHelloRef<'a> {
//    pub(crate) fn parse(client_hello: &'a [u8]) -> Result<Self, CliHelloParseError> {
//        let mut pos = size_of::<ProtocolVersion>();
//        let random_bytes = <&[u8; ClientHello::RANDOM_BYTES_LEN]>::try_from(
//            &client_hello[pos..][..ClientHello::RANDOM_BYTES_LEN],
//        )
//        .unwrap();
//        pos += random_bytes.len();
//
//        let legacy_session_id_len = client_hello[34];
//        pos += 1;
//        if legacy_session_id_len > 32 {
//            return Err(CliHelloParseError::InvalidLengthEncoding);
//        }
//
//        let session_id = &client_hello[pos..][..legacy_session_id_len as usize];
//        pos += legacy_session_id_len as usize;
//
//        let cipher_suites_len = u16::from_be_bytes(client_hello[pos..][..2].try_into().unwrap());
//        pos += 2;
//        if cipher_suites_len > 0xfffe {
//            return Err(CliHelloParseError::InvalidLengthEncoding);
//        }
//
//        let cipher_suites = &client_hello[pos..][..cipher_suites_len as usize];
//        pos += cipher_suites_len as usize;
//
//        let legacy_compression_methods_len = client_hello[pos];
//        pos += 1;
//        pos += legacy_compression_methods_len as usize;
//
//        let extensions = &client_hello[pos + 1..];
//        Ok(Self {
//            random_bytes,
//            session_id,
//            cipher_suites,
//            extensions,
//        })
//    }
//}
