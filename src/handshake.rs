#[repr(C)]
pub enum ShakeStatus {
    /// Indicates a successful handshake
    Success = 0,
    UnexpectedMessage,
}

#[repr(u8)]
pub enum ShakeType {
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

pub struct ShakeMsg {
    msg: Vec<u8>,
}

impl ShakeMsg {
    pub fn new(shake_type: ShakeType, len: u32) -> Self {
        let mut msg = Vec::with_capacity(size_of::<u32>() + len as usize);

        let mut msg_header = len.to_be_bytes();
        msg_header[0] = shake_type as u8;
        msg.extend_from_slice(&msg_header);
        Self { msg }
    }
}

impl std::ops::Deref for ShakeMsg {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.msg
    }
}

impl std::ops::DerefMut for ShakeMsg {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.msg
    }
}

impl std::borrow::Borrow<[u8]> for ShakeMsg {
    fn borrow(&self) -> &[u8] {
        self
    }
}
