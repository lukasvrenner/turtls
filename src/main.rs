/// all sizes represent the number of bytes
const BLOCK_SIZE: usize = 0x10;
const WORD_SIZE: usize = 0x4;

const N_B: usize = 0x4;

type Word = [u8; WORD_SIZE];

macro_rules! cipher {
    ($input:expr, $n_r:literal, $round_keys:expr) => {{
        let state: [u8; 0x10] = $input;
        let round_keys = $round_keys;
        $crate::add_round_key(&mut state, round_keys[0..3]);
        for round in 1..$n_r - 1 {
            $crate::sub_bytes(&mut state);
            $crate::shift_rows(&mut state);
            $crate::mix_columns(&mut state);
            $crate::add_round_key(
                &mut state,
                round_keys[4 * round..4 * round + 3],
            );
        }
        $crate::sub_bytes(&mut state);
        $crate::shift_rows(&mut state);
        $crate::add_round_key(&mut state, round_keys[4 * $n_r..4 * $n_r + 3]);
        state
    }};
}

// we have to use a macro because
// the key has different lengths for each version
macro_rules! key_expansion {
    ($key:expr, $n_r:literal) => {{
        todo!()
    }};
}

fn main() {
    todo!();
}

fn add_round_key(state: &mut [u8; 0x10], round_key: &[u8]) {
    todo!();
}

fn aes_128(input: [u8; 0x10], key: [Word; 4]) -> [u8; 0x10] {
    cipher!(input, 0xA, key_expansion!(key, 0xA))
}

fn aes_192(input: [u8; 0x10], key: [Word; 6]) -> [u8; 0x10] {
    cipher!(input, 0xC, key_expansion!(key, 0xA))
}

fn aes_256(input: [u8; 0x10], key: [Word; 8]) -> [u8; 0x10] {
    cipher!(input, 0xE, key_expansion!(key, 0xA))
}

fn eq_inv_cipher() {
    todo!();
}

fn inv_cipher(input: [u8; 0x10]) {
    todo!();
}

fn inv_mix_columns() {
    todo!();
}

fn inv_s_box() {
    todo!();
}

fn inv_shift_rows() {
    todo!();
}

fn inv_sub_bytes() {
    todo!();
}

fn key_expansion_eic() {
    todo!()
}

fn mix_columns(state: &mut [u8; 0x10]) {
    todo!();
}

fn rotate_words() {
    todo!();
}

fn s_box(byte: u8) {
    let inverse = match byte {
        0 => 0,
        _ => byte.pow(254),
    };
    todo!();
}

fn shift_rows(state: &mut [u8; 0x10]) {
    for row in 0..4 {
        state[row * 4..(row + 1) * 4].rotate_left(row);
    }
}

fn sub_bytes(state: &mut [u8; 0x10]) {
    state.iter_mut().for_each(|byte| s_box(*byte));
}

fn sub_word() {
    todo!();
}

fn x_times() {
    todo!();
}
