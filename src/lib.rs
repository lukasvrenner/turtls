//! AES-256

const NUM_ROUNDS: usize = 14;

type Word = [u8; 4];

type State = [[u8; 4]; 4];

fn key_expansion(key: [Word; 4]) -> [[Word; 4]; NUM_ROUNDS + 1] {
    todo!();
}

fn add_round_key(state: &mut State, round_key: [Word; 4]) {
    for col in 0..state.len() {
        for row in 0..state[0].len() {
            state[col][row] ^= round_key[col][row];
        }
    }
}

pub fn aes_256(input: [u8; 16], key: [Word; 4]) -> [u8; 16] {
    // SAFETY: a 2d array is represented by the same memory as a 1d array
    let mut state: State = unsafe { std::mem::transmute(input) };

    let round_keys = key_expansion(key);

    add_round_key(&mut state, round_keys[0]);
    for round in 1..NUM_ROUNDS {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_keys[round]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, round_keys[NUM_ROUNDS]);

    // use flatten() once stabilized
    unsafe { std::mem::transmute(state) }
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
        col[0] = (0x2 * column[0]) ^ (0x3 * column[1]) ^ column[2] ^ column[3];

        col[1] = column[0] ^ (0x2 * column[1]) ^ (0x3 * column[2]) ^ column[3];

        col[2] = column[0] ^ column[1] ^ (0x2 * column[2]) ^ (0x3 * column[3]);

        col[3] = (0x3 * column[0]) ^ column[1] ^ column[2] ^ (0x2 * column[3]);
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
        .for_each(|col| col.iter_mut().for_each(|byte| s_box(*byte)));
}

#[inline]
fn sub_word(word: &mut Word) {
    word.iter_mut().for_each(|byte| s_box(*byte));
}

fn x_times() {
    todo!();
}
