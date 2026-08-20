//! Key schedule: разворачивание 256-битного мастер-ключа в раундовые подключи.
//!
//! ВАЖНО: это НЕ генерация ключа и не KDF из пароля — этим занимается
//! отдельный крейт `quark-kdf` (Argon2id) или `quark-keygen` (OsRng).
//! Здесь предполагается, что мастер-ключ уже является 256 бит
//! криптографически качественной случайности, и нужно только вывести
//! из него ROUNDS+1 раундовых подключей для AddRoundKey.
//!
//! ⚠️ Как и константы в constants.rs, эта схема предварительная и не
//! проходила формальный анализ на related-key атаки. См. DESIGN_RATIONALE.md.

use crate::constants::{KEY_SCHEDULE_INCREMENT, ROTATIONS, ROUNDS, WORDS};
use crate::round::State;
use zeroize::Zeroize;

/// Раундовые подключи: ROUNDS раундов + 1 финальный whitening-ключ.
#[derive(Clone)]
pub struct RoundKeys(pub Vec<State>);

impl Drop for RoundKeys {
    fn drop(&mut self) {
        for rk in self.0.iter_mut() {
            rk.zeroize();
        }
    }
}

/// Разворачивает 256-битный мастер-ключ (8 слов по 32 бита) в ROUNDS+1
/// раундовых подключей.
///
/// Использует Weyl-последовательность (аналог техники в TEA/XTEA) для
/// генерации раундовых констант и ротацию слов ключа для диффузии между
/// подключами. Каждый следующий подключ зависит от предыдущего состояния
/// ключевого регистра, что не позволяет вывести один подключ из другого
/// без знания мастер-ключа.
pub fn expand_key(master_key: State) -> RoundKeys {
    let mut round_keys = Vec::with_capacity(ROUNDS + 1);
    let mut state = master_key;
    let mut c: u32 = KEY_SCHEDULE_INCREMENT;

    for round in 0..=ROUNDS {
        let mut rk: State = [0; WORDS];
        for j in 0..WORDS {
            let rot = ROTATIONS[(j + round) % WORDS];
            rk[j] = state[j].rotate_left(rot) ^ c.wrapping_mul((j as u32) + 1);
        }
        round_keys.push(rk);

        // Обновляем ключевой регистр для следующего подключа.
        for j in 0..WORDS {
            state[j] = state[j].wrapping_add(c).rotate_left(ROTATIONS[j]);
        }
        c = c.wrapping_add(KEY_SCHEDULE_INCREMENT);
    }

    RoundKeys(round_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_keys_produce_different_schedules() {
        let key_a: State = [1, 2, 3, 4, 5, 6, 7, 8];
        let key_b: State = [1, 2, 3, 4, 5, 6, 7, 9]; // отличается на 1 бит
        let sched_a = expand_key(key_a);
        let sched_b = expand_key(key_b);
        assert_ne!(sched_a.0, sched_b.0, "related keys must yield different schedules");
    }

    #[test]
    fn schedule_has_correct_length() {
        let key: State = [0; WORDS];
        let sched = expand_key(key);
        assert_eq!(sched.0.len(), ROUNDS + 1);
    }
}