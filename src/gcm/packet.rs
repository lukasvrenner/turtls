/// represents encryped GCM data
pub struct Packet {
    value: Vec<u8>,
}

pub const MIN_PACKET_SIZE: usize = 28;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

impl Packet {
    #[inline]
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        self.value[0..NONCE_SIZE].try_into().unwrap()
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.value[NONCE_SIZE..self.value.len() - TAG_SIZE]
    }

    #[inline]
    pub fn tag(&self) -> &[u8; TAG_SIZE] {
        let len = self.value.len();
        self.value[len - TAG_SIZE..len].try_into().unwrap()
    }
}
