//! # Skhoron-Quark keygen
//!
//! Генерация случайного 256-битного ключа напрямую через OS CSPRNG.
//! Используется, когда ключ НЕ привязан к паролю пользователя (например,
//! программная генерация session-ключа, который затем передаётся через
//! отдельный защищённый канал/key exchange — не через эту библиотеку).
//!
//! Если нужен ключ ИЗ ПАРОЛЯ пользователя — используйте `skhoron-quark-kdf`
//! (Argon2id), а не эту библиотеку. Пароли имеют низкую энтропию и требуют
//! медленной, memory-hard функции растяжения — OsRng для паролей не подходит.

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// Генерирует криптостойкий случайный 256-битный (32-байтный) ключ.
pub fn generate_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_key_of_correct_length() {
        let key = generate_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn two_generated_keys_are_different() {
        let key_a = generate_key();
        let key_b = generate_key();
        // Вероятность совпадения двух независимых 256-бит случайных
        // значений пренебрежимо мала (2^-256) — если тест когда-либо
        // упадёт здесь, скорее всего сломан сам RNG, а не тест.
        assert_ne!(*key_a, *key_b);
    }
}