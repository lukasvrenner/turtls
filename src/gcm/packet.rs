/// represents encryped GCM data
pub struct Packet {
    value: Vec<u8>,
}

const MIN_PACKET_SIZE: usize = 28;

impl Packet {

    #[inline]
    pub fn nonce(&self) -> &[u8] {
        &self.value[0..16]
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        todo!();
    }

    #[inline]
    pub fn additional_data(&self) -> &[u8] {
        todo!();
    }

    #[inline]
    pub fn tag(&self) -> &[u8] {
        let len = self.value.len();
        &self.value[len - 16..len]
    }

    pub fn g_hash(
        key: &[u8],
        encrypted_data: &[u8],
        additional_data: &[u8],
    ) -> u128 {
        todo!();
    }
}

pub struct TooShort;

impl TryFrom<Vec<u8>> for Packet {
    type Error = TooShort;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        match data.len().cmp(&MIN_PACKET_SIZE) {
            std::cmp::Ordering::Less => Err(TooShort),
            _ => Ok(Packet { value: data }),
        }
    }
}

impl Into<Vec<u8>> for Packet {
    fn into(self) -> Vec<u8> {
        self.value
    }
}
