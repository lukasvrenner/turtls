// const G: Point = Point::new(
//     FieldEl::new([
//         0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
//         0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
//         0xc2, 0x96,
//     ]),
//     FieldEl::new([
//         0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
//         0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
//         0x51, 0xf5,
//     ]),
// );
//
// const N: FieldEl = FieldEl::new([
//     0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//     0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
// ]);
//
// struct Point(FieldEl, FieldEl);
//
// impl Point {
//     const fn new(x: FieldEl, y: FieldEl) -> Point {
//         Point(x, y)
//     }
//
//     fn mult_scalar(&self, scalar: FieldEl) -> Point {
//         todo!();
//     }
// }

/// Represents a big integer less than `N`
fn generate_signature(
    msg: &[u8],
    key: [u8; 32],
    hash_func: fn(&[u8]) -> [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    // let hash = hash_func(msg);
    // let key = key;
    //
    // let mut r = FieldEl::from([0u8; 32]);
    // let mut s = [0u8; 32];
    //
    // // this will eventually exit because `key`
    // // is generated non-deterministically
    // while r == [0u8; 32] || s == [0u8; 32] {
    //     let scalar = generate_secret_number();
    //     let inverse = inverse(scalar);
    //
    //     let new_point = G.mult_scalar(scalar);
    //     r = new_point.0;
    //     s = inverse * (hash + r * key);
    // }
    // (r, s)
    todo!()
}

// fn generate_secret_number() -> FieldEl {
//     todo!()
// }
//
// fn inverse(num: FieldEl) -> FieldEl {
//     todo!();
// }