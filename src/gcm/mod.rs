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

    pub fn encrypt(&self, data: &[u8]) -> Packet {
        todo!();
    }

    pub fn decrypt(&self, packet: Packet) -> Result<Vec<u8>, InvalidData> {
        match self.packet_is_valid(&packet) {
            true => {
                let mut data = packet.data().to_vec();
                self.xor_bit_stream(packet.nonce(), &mut data);
                Ok(data)
            }
            false => Err(InvalidData),
        }
    }

    /// produces a tag for given data
    pub fn g_hash(&self, encrypted_data: &[u8]) -> &[u8; TAG_SIZE] {
        todo!();
    }

    /// verifies that a give packet has not been tampered with
    pub fn packet_is_valid(&self, packet: &Packet) -> bool {
        self.g_hash(packet.data()) == packet.tag()
    }

    /// encrypts/decrypts the data
    fn xor_bit_stream(&self, nonce: &[u8; NONCE_SIZE], data: &mut [u8]) {
        let nonce_as_int = {
            let mut expanded_nonce = [0u8; 16];
            expanded_nonce[0..nonce.len()].copy_from_slice(nonce);
            u128::from_be_bytes(expanded_nonce)
        };

        for counter in 0..data.len() / aes::BLOCK_SIZE {
            let mut chunk = (nonce_as_int + 1 + counter as u128).to_be_bytes();
            aes::encrypt_inline(&mut chunk, &self.round_keys);

            for (index, byte) in data
                [aes::BLOCK_SIZE * counter..aes::BLOCK_SIZE * (counter + 1)]
                .iter_mut()
                .enumerate()
            {
                *byte ^= chunk[index];
            }
        }
    }
}
