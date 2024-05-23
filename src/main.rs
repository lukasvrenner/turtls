/// all sizes represent the number of bytes

type Word = [u8; 4];

type State = [[u8; 4]; 4];

macro_rules! cipher {
    ($input:expr, $n_r:literal, $words:expr) => {{
        // SAFETY: a 2d array is represented by the same memory as a 1d array
        let state: State = unsafe { std::mem::transmute($input) };
        let round_keys = $words;

        $crate::add_round_key(&mut state, round_keys[0]);
        for round in 0..$n_r {
            $crate::sub_bytes(&mut state);
            $crate::shift_rows(&mut state);
            $crate::mix_columns(&mut state);
            $crate::add_round_key(
                &mut state,
                round_keys[round],
            );
        }
        $crate::sub_bytes(&mut state);
        $crate::shift_rows(&mut state);
        $crate::add_round_key(&mut state, round_keys[$n_r]);

        // use flatten() once stabilized
        unsafe { std::mem::transmute(state) }
    }};
}

// we have to use a macro because
// the key has different lengths for each version
macro_rules! key_expansion {
    ($key:expr, $n_r:literal) => {{
        let words: [Word; $n_r + 1];
        todo!()
    }};
}

fn main() {
    todo!();
}

fn add_round_key(state: &mut State, round_key: [Word; 4]) {
    for col in 0..state.len() {
        for row in 0..state[0].len() {
            state[col][row] ^= round_key[col][row];
        }
    }
}

fn aes_128(input: [u8; 16], key: [Word; 4]) -> [u8; 16] {
    cipher!(input, 10, key_expansion!(key, 10))
}

fn aes_192(input: [u8; 16], key: [Word; 6]) -> [u8; 16] {
    cipher!(input, 14, key_expansion!(key, 12))
}

fn aes_256(input: [u8; 16], key: [Word; 8]) -> [u8; 16] {
    cipher!(input, 14, key_expansion!(key, 14))
}

fn eq_inv_cipher() {
    todo!();
}

fn inv_cipher(input: [u8; 16]) {
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

fn mix_columns(state: &mut State) {
    for col in state {
        let column = col.clone();
        col[0] =
            (0x2 * column[0]) ^ (0x3 * column[1]) ^ column[2] ^ column[3];

        col[1] = 
            column[0] ^ (0x2 * column[1]) ^ (0x3 * column[2]) ^ column[3];

        col[2] = 
            column[0] ^ column[1] ^ (0x2 * column[2]) ^ (0x3 * column[3]);

        col[3] =
            (0x3 * column[0]) ^ column[1] ^ column[2] ^ (0x2 * column[3]);
    }
}

#[inline]
fn rotate_word(word: &mut Word) {
    word.rotate_left(1);
}

fn s_box(byte: u8) {
    todo!();
}

#[inline]
fn shift_rows(state: &mut State) {
    todo!();
}

#[inline]
fn sub_bytes(state: &mut State) {
    state
        .iter_mut()
        .for_each(|row| row.iter_mut().for_each(|byte| s_box(*byte)));
}

#[inline]
fn sub_word(word: &mut Word) {
    word.iter_mut().for_each(|byte| s_box(*byte));
}

fn x_times() {
    todo!();
}
