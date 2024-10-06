//! A software implementation of SHA-256.

use super::{BlockHasher, Hasher};

/// The first 32 bits of the fractional parts of
/// the cube roots of the first 64 prime numbers
// TODO: name this something useful
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A one-time helper function used by `update_hash()`
// TODO: name this something useful
#[inline]
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// A one-time helper function used by `update_hash()`
// TODO: name this something useful
#[inline]
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// A one-time helper function used by `update_hash()`
// TODO: name this something useful
#[inline]
const fn sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// A one-time helper function used by `update_hash()`
// TODO: name this something useful
#[inline]
const fn sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// A one-time helper function used by `update_hash()`
// TODO: name this something useful
#[inline]
const fn little_sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}

/// A one-time helper function used by `update_hash()`
// TODO: name this something useful
#[inline]
const fn little_sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

pub struct Sha256 {
    state: [u32; Self::HASH_SIZE / size_of::<u32>()],
}

impl Hasher<{ Sha256::HASH_SIZE }> for Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
        }
    }
    fn finish_with(mut self, msg: &[u8]) -> [u8; Self::HASH_SIZE] {
        // TODO: use `array_chunks` once stabilized
        let blocks = msg.chunks_exact(Self::BLOCK_SIZE);
        let remainder = blocks.remainder();

        for block in blocks {
            self.update(block.try_into().unwrap());
        }

        let mut last_block = [0; Self::BLOCK_SIZE];
        // we can safely write here because the excess must be less than `BLOCK_SIZE`
        last_block[..remainder.len()].copy_from_slice(remainder);

        last_block[remainder.len()] = 0x80;

        // does the length info fit without adding an extra block?
        if remainder.len() < Self::BLOCK_SIZE - size_of::<u64>() {
            last_block[Self::BLOCK_SIZE - size_of::<u64>()..]
                .copy_from_slice(&(msg.len() as u64 * 8).to_be_bytes());
        } else {
            self.update(&last_block);
            last_block = [0; Self::BLOCK_SIZE];
            last_block[Self::BLOCK_SIZE - size_of::<u64>()..]
                .copy_from_slice(&(msg.len() as u64 * 8).to_be_bytes());
        }

        self.update(&last_block);
        self.finish()
    }

    fn hash(msg: &[u8]) -> [u8; Sha256::HASH_SIZE] {
        let hasher = Self::new();
        hasher.finish_with(msg)
    }

    fn finish(self) -> [u8; Self::HASH_SIZE] {
        // TODO: consider using uninitialized array
        let mut as_bytes = [0u8; Sha256::HASH_SIZE];
        // TODO: use `array_chunks` once stabilized
        for (chunk, int) in as_bytes.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&int.to_be_bytes())
        }
        as_bytes
    }
}

impl BlockHasher<{ Sha256::HASH_SIZE }, { Sha256::BLOCK_SIZE }> for Sha256 {
    fn update(&mut self, block: &[u8; Self::BLOCK_SIZE]) {
        let block = {
            // TODO: consider using uninitialized array
            let mut as_u32 = [0u32; Sha256::BLOCK_SIZE / 4];
            // TODO: use `array_chunks` once stabilized
            for (int, chunk) in as_u32.iter_mut().zip(block.chunks_exact(4)) {
                *int = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            as_u32
        };

        let mut message_schedule = [0; 64];
        message_schedule[..block.len()].copy_from_slice(&block);

        for i in 16..message_schedule.len() {
            message_schedule[i] = little_sigma_1(message_schedule[i - 2])
                .wrapping_add(message_schedule[i - 7])
                .wrapping_add(little_sigma_0(message_schedule[i - 15]))
                .wrapping_add(message_schedule[i - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let temp1 = h
                .wrapping_add(sigma_1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(message_schedule[i]);
            let temp2 = sigma_0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Sha256 {
    pub const HASH_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 64;
}

#[cfg(test)]
mod tests {
    use super::{Hasher, Sha256};
    #[test]
    fn sha256() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest: [u8; Sha256::HASH_SIZE] = [
            0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E,
            0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4,
            0x19, 0xDB, 0x06, 0xC1,
        ];
        assert_eq!(Sha256::hash(msg), digest);
    }
}
