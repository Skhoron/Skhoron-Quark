//! 256-битный блочный шифр Skhoron-Quark: собирает round-function и
//! key schedule в encrypt_block/decrypt_block.

use crate::constants::ROUNDS;
use crate::key_schedule::{expand_key, RoundKeys};
use crate::round::{forward_round, inverse_round, State};
use zeroize::Zeroize;

/// 256-битный блок (8 слов по 32 бита = 32 байта).
pub const BLOCK_SIZE_BYTES: usize = 32;

fn xor_state(state: &mut State, key: &State) {
    for i in 0..8 {
        state[i] ^= key[i];
    }
}

fn bytes_to_state(bytes: &[u8; BLOCK_SIZE_BYTES]) -> State {
    let mut state = [0u32; 8];
    for i in 0..8 {
        state[i] = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    state
}

fn state_to_bytes(state: &State) -> [u8; BLOCK_SIZE_BYTES] {
    let mut out = [0u8; BLOCK_SIZE_BYTES];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Держатель мастер-ключа и развёрнутого расписания подключей.
/// Реализует Zeroize при выходе из scope (и для самого ключа, и для
/// раундовых подключей — см. Drop у RoundKeys).
pub struct QuarkKey {
    round_keys: RoundKeys,
}

impl QuarkKey {
    /// Создаёт QuarkKey из 32-байтного (256-бит) ключа.
    /// Ключ должен быть получен из криптостойкого источника —
    /// см. крейты `quark-keygen` (случайный ключ) или `quark-kdf` (из пароля).
    pub fn new(mut key_bytes: [u8; 32]) -> Self {
        let master_state = bytes_to_state(&key_bytes);
        let round_keys = expand_key(master_state);
        key_bytes.zeroize();
        Self { round_keys }
    }

    /// Шифрует один 256-битный блок.
    pub fn encrypt_block(&self, plaintext: &[u8; BLOCK_SIZE_BYTES]) -> [u8; BLOCK_SIZE_BYTES] {
        let mut state = bytes_to_state(plaintext);
        let rk = &self.round_keys.0;

        for r in 0..ROUNDS {
            xor_state(&mut state, &rk[r]);
            forward_round(&mut state);
        }
        xor_state(&mut state, &rk[ROUNDS]); // финальный whitening-ключ

        let out = state_to_bytes(&state);
        state.zeroize();
        out
    }

    /// Расшифровывает один 256-битный блок.
    pub fn decrypt_block(&self, ciphertext: &[u8; BLOCK_SIZE_BYTES]) -> [u8; BLOCK_SIZE_BYTES] {
        let mut state = bytes_to_state(ciphertext);
        let rk = &self.round_keys.0;

        xor_state(&mut state, &rk[ROUNDS]);
        for r in (0..ROUNDS).rev() {
            inverse_round(&mut state);
            xor_state(&mut state, &rk[r]);
        }

        let out = state_to_bytes(&state);
        state.zeroize();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = QuarkKey::new([0x42; 32]);
        let plaintext = [0x11u8; BLOCK_SIZE_BYTES];
        let ciphertext = key.encrypt_block(&plaintext);
        assert_ne!(ciphertext, plaintext, "ciphertext must differ from plaintext");
        let decrypted = key.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext, "decrypt(encrypt(x)) must equal x");
    }

    #[test]
    fn roundtrip_holds_for_many_keys_and_blocks() {
        let mut seed: u64 = 0x0123_4567_89AB_CDEF;
        for _ in 0..200 {
            let mut key_bytes = [0u8; 32];
            let mut plaintext = [0u8; BLOCK_SIZE_BYTES];
            for b in key_bytes.iter_mut().chain(plaintext.iter_mut()) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            let key = QuarkKey::new(key_bytes);
            let ct = key.encrypt_block(&plaintext);
            let pt2 = key.decrypt_block(&ct);
            assert_eq!(pt2, plaintext);
        }
    }

    #[test]
    fn different_keys_give_different_ciphertext_for_same_plaintext() {
        let plaintext = [0xABu8; BLOCK_SIZE_BYTES];
        let key_a = QuarkKey::new([0x01; 32]);
        let key_b = QuarkKey::new([0x02; 32]);
        assert_ne!(key_a.encrypt_block(&plaintext), key_b.encrypt_block(&plaintext));
    }
}