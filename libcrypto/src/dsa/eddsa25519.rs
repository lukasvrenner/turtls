struct Point([u8; 32]);

// numbers are encoded little-endian
impl Point {
    fn new(x: [u8; 32], y: [u8; 32]) -> Point {
        let mut point = y;
        // set the most significant bit of `point`
        // to the least significant bit of `x`
        point[31] = (point[31] & !(1 << 7)) | (x[0] & 1) << 7;
        Point(point)
    }

    fn decode(&self) -> ([u8; 32], [u8; 32]) {
        let x_0 = (self.0[31] & (1 << 7)) >> 7;
        let mut y = self.0;
        // clear most significant bit
        y[31] &= !(1 << 7);

        todo!();
    }
}

impl From<([u8; 32], [u8; 32])> for Point {
    fn from(value: ([u8; 32], [u8; 32])) -> Self {
        Self::new(value.0, value.1)
    }
}
