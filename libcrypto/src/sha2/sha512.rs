//! A software implementation of SHA-512.

use super::{BlockHasher, Hasher};

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

const fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

const fn sigma_0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

const fn sigma_1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

const fn little_sigma_0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ x >> 7
}

const fn little_sigma_1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ x >> 6
}

pub struct Sha512 {
    state: [u64; Self::HASH_SIZE / size_of::<u64>()],
    len: u128,
}

impl Hasher<{ Sha512::HASH_SIZE }> for Sha512 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            len: 0,
        }
    }

    fn finish_with(mut self, msg: &[u8]) -> [u8; Self::HASH_SIZE] {
        // TODO: use `array_chunks` once stabilized
        let chunks = msg.chunks_exact(Self::BLOCK_SIZE);
        let remainder = chunks.remainder();

        for block in chunks {
            self.update_countless(&block.try_into().unwrap());
        }

        let mut last_block = [0; Self::BLOCK_SIZE];
        // we can safely write here because the excess must be less than `BLOCK_SIZE`
        last_block[..remainder.len()].copy_from_slice(remainder);

        last_block[remainder.len()] = 0x80;

        // does the length info fit without adding an extra block?
        if remainder.len() < Self::BLOCK_SIZE - size_of::<u128>() {
            last_block[Self::BLOCK_SIZE - size_of::<u128>()..]
                .copy_from_slice(&((msg.len() as u128 + self.len) * 8).to_be_bytes());
        } else {
            self.update_countless(&last_block);
            last_block = [0; Self::BLOCK_SIZE];
            last_block[Self::BLOCK_SIZE - size_of::<u128>()..]
                .copy_from_slice(&((msg.len() as u128 + self.len) * 8).to_be_bytes());
        }

        self.update(&last_block);
        u64_array_to_be_bytes(&self.state)
    }

    fn finish(mut self) -> [u8; Self::HASH_SIZE] {
        let mut padding = [0; Self::BLOCK_SIZE];
        padding[0] = 0x80;
        padding[Self::BLOCK_SIZE - size_of::<u128>()..]
            .copy_from_slice(&(self.len as u128 * 8).to_be_bytes());
        self.update_countless(&padding);

        u64_array_to_be_bytes(&self.state)
    }

    fn hash(msg: &[u8]) -> [u8; Self::HASH_SIZE] {
        let hasher = Self::new();
        hasher.finish_with(msg)
    }
}

impl BlockHasher<{ Sha512::HASH_SIZE }, { Sha512::BLOCK_SIZE }> for Sha512 {
    fn update(&mut self, block: &[u8; Self::BLOCK_SIZE]) {
        self.update_countless(block);
        self.len += 1;
    }
}

impl Sha512 {
    pub const HASH_SIZE: usize = 64;
    pub const BLOCK_SIZE: usize = 128;

    fn update_countless(&mut self, block: &[u8; Self::BLOCK_SIZE]) {
        let block = be_bytes_to_u64_array(block);
        let mut message_schedule = [0; 80];
        message_schedule[..block.len()].copy_from_slice(&block);

        for i in 16..message_schedule.len() {
            message_schedule[i] = little_sigma_1(message_schedule[i - 2])
                .wrapping_add(message_schedule[i - 7])
                .wrapping_add(little_sigma_0(message_schedule[i - 15]))
                .wrapping_add(message_schedule[i - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..80 {
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

fn be_bytes_to_u64_array(bytes: &[u8; Sha512::BLOCK_SIZE]) -> [u64; Sha512::BLOCK_SIZE / 8] {
    // TODO: consider using uninitialized array
    let mut as_u64 = [64; Sha512::BLOCK_SIZE / 8];
    // TODO: use `array_chunks` once stabilized
    for (int, chunk) in as_u64.iter_mut().zip(bytes.chunks_exact(8)) {
        // we can safely unwrap because `chunk` is guaranteed to have a length of `8`
        *int = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    as_u64
}

fn u64_array_to_be_bytes(array: &[u64; Sha512::HASH_SIZE / size_of::<u64>()]) -> [u8; Sha512::HASH_SIZE] {
    // TODO: consider using uninitialized array
    let mut as_bytes = [0u8; Sha512::HASH_SIZE];
    // TODO: use `array_chunks` once stabilized
    for (chunk, int) in as_bytes.chunks_exact_mut(8).zip(array) {
        chunk.copy_from_slice(&int.to_be_bytes())
    }
    as_bytes
}

#[cfg(test)]
mod tests {

    use super::{Hasher, Sha512};

    #[test]
    fn sha512() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = [
            0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08,
            0xa4, 0x16, 0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31,
            0xa7, 0x03, 0xc3, 0x35, 0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d,
            0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0, 0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03,
            0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45,
        ];
        assert_eq!(hash, Sha512::hash(msg));
        // TODO: make more exaustive tests
    }
}
