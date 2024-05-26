use aes::encrypt;
fn main() {
    // let input = [
    //     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    //     0xcc, 0xdd, 0xee, 0xff,
    // ];
    let input = b"this information is confidential, for your eyes only";
    let key = [0x00u8; 32];
    let encrypted = encrypt(input, &key);
    println!("{:?}", encrypted);
}
