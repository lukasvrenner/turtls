pub mod packet;
use crate::aes;

use self::packet::{Packet, IV_SIZE, TAG_SIZE};
pub struct GcmCipher {
    round_keys: [[u8; aes::BLOCK_SIZE]; aes::NUM_ROUNDS + 1],
    h: [u8; aes::BLOCK_SIZE],
}

pub struct InvalidData;

impl GcmCipher {
    pub fn new(key: [u8; 32]) -> GcmCipher {
        let mut h = [0u8; aes::BLOCK_SIZE];
        let round_keys = aes::expand_key(key);
        aes::encrypt_inline(&mut h, &round_keys);
        GcmCipher { round_keys, h }
    }

    pub fn encrypt(&self, data: &[u8], init_vector: &[u8; IV_SIZE]) -> Packet {
        let mut packet_vec =
            Vec::with_capacity(IV_SIZE + data.len() + TAG_SIZE);

        let mut encrypted_data = data.to_vec();
        self.xor_bit_stream(&mut encrypted_data, init_vector);

        let tag = self.g_hash(&encrypted_data);

        packet_vec.extend_from_slice(init_vector);
        packet_vec.extend_from_slice(&encrypted_data);
        packet_vec.extend_from_slice(&tag);

        debug_assert_eq!(packet_vec.len(), packet_vec.capacity());
        packet_vec.try_into().unwrap()
    }

    pub fn decrypt(&self, packet: Packet) -> Result<Vec<u8>, InvalidData> {
        match self.packet_is_valid(&packet) {
            true => {
                let mut data = packet.data().to_vec();
                self.xor_bit_stream(&mut data, packet.init_vector());
                Ok(data)
            }
            false => Err(InvalidData),
        }
    }

    pub fn generate_iv() -> [u8; IV_SIZE] {
        todo!();
    }

    /// produces a tag for given data
    pub fn g_hash(&self, encrypted_data: &[u8]) -> [u8; TAG_SIZE] {
        todo!();
    }

    /// verifies that a give packet has not been tampered with
    pub fn packet_is_valid(&self, packet: &Packet) -> bool {
        self.g_hash(packet.data()) == *packet.tag()
    }

    /// encrypts/decrypts the data
    // use multi-threading in the future
    fn xor_bit_stream(&self, data: &mut [u8], init_vector: &[u8; IV_SIZE]) {
        let iv_as_int = {
            let mut expanded_iv = [0u8; 16];
            expanded_iv[0..init_vector.len()].copy_from_slice(init_vector);
            u128::from_be_bytes(expanded_iv)
        };

        for (counter, block) in data.chunks_mut(aes::BLOCK_SIZE).enumerate() {
            let mut stream = (iv_as_int + 2 + counter as u128).to_be_bytes();
            aes::encrypt_inline(&mut stream, &self.round_keys);
            println!("{:?}", stream);

            for (data_byte, stream_byte) in block.iter_mut().zip(stream) {
                *data_byte ^= stream_byte;
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn ctr_mode() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f,
            0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
            0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let mut plain_text = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09,
            0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34,
            0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c,
            0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24,
            0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6,
            0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let initialization_vector = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8,
            0x88,
        ];
        let cipher_text = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37,
            0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5,
            0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c,
            0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10,
            0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a,
            0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
        ];
        let cipher = super::GcmCipher::new(key);
        cipher.xor_bit_stream(&mut plain_text, &initialization_vector);
        assert_eq!(plain_text, cipher_text);
    }
}
