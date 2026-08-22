//! Генерация пароля через rejection sampling.
//!
//! Источник случайности — OsRng (crate `rand`), библиотечный, не наш.
//! Сам алгоритм отбора символов из алфавита — наш код.
//!
//! ## Почему не `OsRng.next_u32() % alphabet.len()`
//!
//! Наивный modulo даёт смещённое распределение. Rejection sampling это
//! устраняет — см. `generate_password` ниже.
//!
//! ## Исправленный off-by-one (см. ревью)
//!
//! Диапазон `u32` — это `2^32` различных значений (`0..=u32::MAX`).
//! Предыдущая версия считала `limit` от `u32::MAX`, а не от `2^32`:
//! ```text
//! let limit = u32::MAX - (u32::MAX % n);   // БЫЛО: чуть занижает limit
//! ```
//! Корректно — считать от полного диапазона через `u64`, чтобы не
//! переполниться:
//! ```text
//! let range = 1u64 << 32;
//! let limit = range - (range % n as u64);
//! ```
//! На практике разница даёт отклонение не более чем на 1 из `2^32`
//! значений — не измеримо статистически ни при каком реальном объёме
//! паролей. Тем не менее, раз README заявляет "строго равномерное
//! распределение", формула должна быть точной, а не приближённой.

use crate::charset::CharsetOptions;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Разумный верхний предел длины пароля — защита от случайного OOM при
/// вводе огромного числа (например, опечатка лишнего нуля в CLI-аргументе).
pub const MAX_PASSWORD_LENGTH: usize = 4096;

/// Верхний предел количества генерируемых кандидатов за один вызов —
/// та же защита от случайного `--count 999999999`.
pub const MAX_CANDIDATE_COUNT: usize = 1000;

#[derive(Debug, Error)]
pub enum GeneratorError {
    #[error("password length must be > 0")]
    ZeroLength,
    #[error("password length {0} exceeds maximum of {MAX_PASSWORD_LENGTH}")]
    LengthTooLarge(usize),
    #[error("candidate count {0} exceeds maximum of {MAX_CANDIDATE_COUNT}")]
    CountTooLarge(usize),
    #[error("charset is empty after applying options — enable at least one character class")]
    EmptyCharset,
}

/// Генерирует пароль длины `length` (в СИМВОЛАХ, не байтах — см. ниже)
/// из алфавита, построенного по `opts`.
///
/// ## Исправленный Unicode-баг (см. ревью)
///
/// Предыдущая версия использовала `while password.len() < length`.
/// `String::len()` в Rust возвращает число БАЙТ, а не символов — для
/// произвольного `&str`-алфавита с многобайтовыми символами это дало бы
/// пароль КОРОЧЕ ожидаемой длины в символах. Наши встроенные алфавиты
/// (LOWER/UPPER/DIGITS/SYMBOLS) — чистый ASCII (1 байт = 1 символ), поэтому
/// баг не проявлялся на практике, но это была ошибка публичного API,
/// которая проявилась бы при любом расширении на не-ASCII алфавиты.
/// Теперь считаем именно количество вставленных символов явным счётчиком.
///
/// Возвращает `Zeroizing<String>` — буфер автоматически зануляется при
/// выходе из scope. Это не решает вопрос "пароль уже был выведен в
/// stdout" (терминал/буферизация — вне контроля программы), но защищает
/// от случайного попадания в memory dump после того, как переменная
/// вышла из области видимости.
pub fn generate_password(length: usize, opts: CharsetOptions) -> Result<Zeroizing<String>, GeneratorError> {
    if length == 0 {
        return Err(GeneratorError::ZeroLength);
    }
    if length > MAX_PASSWORD_LENGTH {
        return Err(GeneratorError::LengthTooLarge(length));
    }

    let alphabet = crate::charset::build_charset(opts);
    if alphabet.is_empty() {
        return Err(GeneratorError::EmptyCharset);
    }

    let n = alphabet.len() as u64;
    let range: u64 = 1u64 << 32; // 2^32 — полный диапазон значений u32
    let limit = range - (range % n);

    let mut password = Zeroizing::new(String::with_capacity(length));
    let mut rng = OsRng;
    let mut inserted = 0usize; // счётчик СИМВОЛОВ, не байт

    while inserted < length {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let val = u32::from_le_bytes(buf) as u64;
        buf.zeroize();

        if val >= limit {
            continue; // rejection: отбрасываем смещённый "хвост" диапазона
        }
        let idx = (val % n) as usize;
        password.push(alphabet[idx]);
        inserted += 1;
    }

    Ok(password)
}

/// Генерирует несколько независимых паролей-кандидатов.
/// Ограничен `MAX_CANDIDATE_COUNT`, чтобы `--count` с опечаткой не привёл
/// к попытке выделить огромный объём памяти.
pub fn generate_candidates(
    count: usize,
    length: usize,
    opts: CharsetOptions,
) -> Result<Vec<Zeroizing<String>>, GeneratorError> {
    if count > MAX_CANDIDATE_COUNT {
        return Err(GeneratorError::CountTooLarge(count));
    }
    (0..count).map(|_| generate_password(length, opts)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charset::CharsetOptions;

    #[test]
    fn generates_password_of_correct_character_length() {
        let pw = generate_password(20, CharsetOptions::default()).unwrap();
        assert_eq!(pw.chars().count(), 20);
    }

    #[test]
    fn rejects_zero_length() {
        assert!(matches!(
            generate_password(0, CharsetOptions::default()),
            Err(GeneratorError::ZeroLength)
        ));
    }

    #[test]
    fn rejects_length_above_max() {
        assert!(matches!(
            generate_password(MAX_PASSWORD_LENGTH + 1, CharsetOptions::default()),
            Err(GeneratorError::LengthTooLarge(_))
        ));
    }

    #[test]
    fn rejects_count_above_max() {
        assert!(matches!(
            generate_candidates(MAX_CANDIDATE_COUNT + 1, 10, CharsetOptions::default()),
            Err(GeneratorError::CountTooLarge(_))
        ));
    }

    #[test]
    fn rejects_empty_charset() {
        let opts = CharsetOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(matches!(
            generate_password(10, opts),
            Err(GeneratorError::EmptyCharset)
        ));
    }

    #[test]
    fn two_generated_passwords_differ() {
        let a = generate_password(32, CharsetOptions::default()).unwrap();
        let b = generate_password(32, CharsetOptions::default()).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn works_correctly_for_every_charset_size_from_single_class() {
        // Регрессия на rejection sampling: проверяем корректную работу
        // (без паники, правильная длина) для нескольких разных размеров
        // алфавита, включая маленькие (граничные случаи для limit/n).
        for opts in [
            CharsetOptions { lower: true, upper: false, digits: false, symbols: false, exclude_ambiguous: false },
            CharsetOptions { lower: false, upper: false, digits: true, symbols: false, exclude_ambiguous: false },
            CharsetOptions::default(),
        ] {
            let pw = generate_password(50, opts).unwrap();
            assert_eq!(pw.chars().count(), 50);
        }
    }

    #[test]
    fn very_long_password_within_limit_succeeds() {
        let pw = generate_password(MAX_PASSWORD_LENGTH, CharsetOptions::default()).unwrap();
        assert_eq!(pw.chars().count(), MAX_PASSWORD_LENGTH);
    }

    #[test]
    fn count_zero_returns_empty_vec() {
        let candidates = generate_candidates(0, 10, CharsetOptions::default()).unwrap();
        assert!(candidates.is_empty());
    }

    #[test]
    fn distribution_is_reasonably_uniform_across_alphabet() {
        let opts = CharsetOptions::default();
        let alphabet = crate::charset::build_charset(opts);
        let long_password = generate_password(50_000, opts).unwrap();

        let mut counts = std::collections::HashMap::new();
        for c in long_password.chars() {
            *counts.entry(c).or_insert(0u32) += 1;
        }

        let expected = 50_000.0 / alphabet.len() as f64;
        for &count in counts.values() {
            let deviation = (count as f64 - expected).abs() / expected;
            assert!(
                deviation < 0.25,
                "character frequency deviates too much from uniform: {count} vs expected ~{expected:.0}"
            );
        }
    }
}