pub mod packet;

use std::array::TryFromSliceError;
pub struct GcmCipher {
    key: [u8; 32],
}

pub struct InvalidData;

impl GcmCipher {
    pub const fn new(key: [u8; 32]) -> GcmCipher {
        GcmCipher { key }
    }

    pub fn encrypt(data: &[u8]) -> Packet {
        todo!();
    }

    pub fn decrypt(packet: Packet) -> Result<Vec<u8>, InvalidData> {
        todo!();
    }
}
