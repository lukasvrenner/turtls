pub mod packet;
use crate::aes;

use self::packet::{Packet, NONCE_SIZE, TAG_SIZE};
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

    pub fn encrypt(&self, data: &[u8], nonce: &[u8; NONCE_SIZE]) -> Packet {
        let mut packet_vec =
            Vec::with_capacity(NONCE_SIZE + data.len() + TAG_SIZE);

        let mut encrypted_data = data.to_vec();
        self.xor_bit_stream(&mut encrypted_data, nonce);

        let tag = self.g_hash(&encrypted_data);

        packet_vec.extend_from_slice(nonce);
        packet_vec.extend_from_slice(&encrypted_data);
        packet_vec.extend_from_slice(&tag);

        debug_assert_eq!(packet_vec.len(), packet_vec.capacity());
        packet_vec.try_into().unwrap()
    }

    pub fn decrypt(&self, packet: Packet) -> Result<Vec<u8>, InvalidData> {
        match self.packet_is_valid(&packet) {
            true => {
                let mut data = packet.data().to_vec();
                self.xor_bit_stream(&mut data, packet.nonce());
                Ok(data)
            }
            false => Err(InvalidData),
        }
    }

    pub fn generate_nonce() -> [u8; NONCE_SIZE] {
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
    fn xor_bit_stream(&self,  data: &mut [u8], nonce: &[u8; NONCE_SIZE]) {
        let nonce_as_int = {
            let mut expanded_nonce = [0u8; 16];
            expanded_nonce[0..nonce.len()].copy_from_slice(nonce);
            u128::from_be_bytes(expanded_nonce)
        };

        for counter in 0..data.len() / aes::BLOCK_SIZE {
            let mut chunk = (nonce_as_int + 1 + counter as u128).to_be_bytes();
            aes::encrypt_inline(&mut chunk, &self.round_keys);

            for (data_byte, stream_byte) in data
                [aes::BLOCK_SIZE * counter..aes::BLOCK_SIZE * (counter + 1)]
                .iter_mut()
                .zip(chunk)
            {
                *data_byte ^= stream_byte;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NONCE_SIZE;

    #[test]
    fn ctr_mode() {
        let key = [0u8; 32];
        let mut plain_text = [0u8; 16];
        let initialization_vector = [0u8; NONCE_SIZE];
        let cipher_text: [u8; 16] = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5,
            0xd3, 0xba, 0xf3, 0x9d, 0x18,
        ];
        let cipher = super::GcmCipher::new(key);
        cipher.xor_bit_stream(&mut plain_text, &initialization_vector);
        assert_eq!(plain_text, cipher_text);
    }
}
