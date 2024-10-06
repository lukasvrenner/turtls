use super::{BlockHasher, BufHasher};

pub struct Hmac<const H_LEN: usize, const B_LEN: usize, H>
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    state: H,
    opad: [u8; B_LEN],
}

impl<const H_LEN: usize, const B_LEN: usize, H> Hmac<H_LEN, B_LEN, H>
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    pub fn new(key: &[u8]) -> Self {
        let mut ipad = [0x36; B_LEN];
        let mut opad = [0x5c; B_LEN];
        for ((ipad_byte, opad_byte), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
            *ipad_byte ^= key_byte;
            *opad_byte ^= key_byte;
        }

        let mut state = H::new();
        state.update(&ipad);
        Self { state, opad }
    }

    pub fn update(&mut self, block: &[u8; B_LEN]) {
        self.state.update(block);
    }

    pub fn finish_with(self, msg: &[u8]) -> [u8; H_LEN] {
        let inner_hash = self.state.finish_with(msg);
        outer_finish::<H_LEN, B_LEN, H>(&self.opad, &inner_hash)
    }

    pub fn finish(self) -> [u8; H_LEN] {
        let inner_hash = self.state.finish();
        outer_finish::<H_LEN, B_LEN, H>(&self.opad, &inner_hash)
    }

    pub fn auth(msg: &[u8], key: &[u8]) -> [u8; H_LEN] {
        let state = Self::new(key);
        state.finish_with(msg)
    }
}

impl<const H_LEN: usize, const B_LEN: usize, H> Hmac<H_LEN, B_LEN, BufHasher<H_LEN, B_LEN, H>>
where H: BlockHasher<H_LEN, B_LEN> {
    fn update_with(&mut self, msg: &[u8]) {
        self.state.update_with(msg)
    }
}

fn outer_finish<const H_LEN: usize, const B_LEN: usize, H>(
    opad: &[u8; B_LEN],
    inner_hash: &[u8; H_LEN],
) -> [u8; H_LEN]
where
    H: BlockHasher<H_LEN, B_LEN>,
{
    let mut hasher = H::new();
    hasher.update(opad);
    hasher.finish_with(inner_hash)
}
