//! Key schedule: разворачивание 256-битного мастер-ключа в раундовые подключи.
//!
//! ВАЖНО: это НЕ генерация ключа и не KDF из пароля — этим занимается
//! отдельный крейт `quark-kdf` (Argon2id) или `quark-keygen` (OsRng).
//! Здесь предполагается, что мастер-ключ уже является 256 бит
//! криптографически качественной случайности.
//!
//! ## Редизайн после найденного изъяна (см. ревью)
//!
//! Первая версия использовала независимое обновление каждого слова
//! ключевого регистра (`state[j] = state[j].wrapping_add(c).rotate_left(...)`)
//! без какого-либо смешивания МЕЖДУ словами. Экспериментальная проверка
//! подтвердила: флип одного бита в слове[0] мастер-ключа влиял только на
//! слово[0] во ВСЕХ раундовых подключах, вплоть до 24-го раунда — то есть
//! key schedule был структурно проще, чем сам round-function, и
//! потенциально уязвим к related-key анализу (нет диффузии между словами
//! ключа в принципе).
//!
//! Промежуточная попытка (добавить только cross-XOR + permutation без
//! Sum-layer) улучшила ситуацию, но диффузия стабилизировалась на 4 из 8
//! слов и не доходила до полной — обнаружено той же экспериментальной
//! проверкой.
//!
//! Финальное решение: key schedule переиспользует уже провалидированный
//! `round::forward_round` (тот же самый round-function, что и в самом
//! шифровании, включая Sum-layer — единственный источник нелинейности) в
//! качестве функции обновления ключевого регистра, с инъекцией
//! Weyl-константы перед каждым раундом (защита от slide-атак — без
//! константы raunds были бы неразличимы для атакующего, ищущего
//! self-similar паттерны). Экспериментально подтверждено: полная
//! диффузия (8/8 слов, ~50% бит) достигается уже к 4-му раунду key
//! schedule и остаётся стабильной. Архитектурно это также означает
//! меньше уникального кода для анализа — одна и та же функция смешивания
//! используется и в шифровании, и в key schedule.

use crate::constants::{KEY_SCHEDULE_INCREMENT, ROUNDS, WORDS};
use crate::round::{forward_round, State};
use zeroize::Zeroize;

/// Раундовые подключи: ROUNDS раундов + 1 финальный whitening-ключ.
///
/// НЕ реализует `Clone` намеренно (было исправлено — раньше был
/// `#[derive(Clone)]`). Это секретный материал: `Drop` зануляет память
/// конкретного экземпляра, но клон получил бы отдельную независимую копию
/// векторов, которую `Drop` оригинала никак не затронул бы — то есть
/// секрет мог бы пережить предполагаемую очистку в памяти клона. Раз
/// клонирование `RoundKeys` нигде реально не требуется (используется
/// только внутри `QuarkKey`, которая владеет им напрямую), безопаснее
/// вообще не давать такую возможность на уровне типа.
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
/// Каждый раундовый подключ — это состояние ключевого регистра ПОСЛЕ
/// XOR с раунд-константой (Weyl-последовательность, техника из TEA/XTEA,
/// защита от slide-атак) и одного применения `forward_round` (та же
/// функция смешивания, что и в самом шифровании).
pub fn expand_key(master_key: State) -> RoundKeys {
    let mut round_keys = Vec::with_capacity(ROUNDS + 1);
    let mut state = master_key;
    let mut c: u32 = KEY_SCHEDULE_INCREMENT;

    for _ in 0..=ROUNDS {
        for j in 0..WORDS {
            state[j] ^= c.wrapping_mul((j as u32) + 1);
        }
        forward_round(&mut state);
        round_keys.push(state);
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
        let key_b: State = [1, 2, 3, 4, 5, 6, 7, 9];
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

    #[test]
    fn single_bit_key_difference_diffuses_into_all_words_within_a_few_rounds() {
        // Регрессионный тест на найденный и исправленный изъян: раньше
        // разница в одном слове ключа никогда не покидала это слово,
        // даже после всех 24 раундов key schedule. Проверяем, что теперь
        // 4-й же раундовый подключ отличается уже во ВСЕХ 8 словах.
        let key_a: State = [0; WORDS];
        let mut key_b: State = [0; WORDS];
        key_b[0] = 1; // один бит в слове[0]

        let sched_a = expand_key(key_a);
        let sched_b = expand_key(key_b);

        let round_key_4_a = sched_a.0[3];
        let round_key_4_b = sched_b.0[3];

        let untouched: Vec<usize> = (0..WORDS).filter(|&i| round_key_4_a[i] == round_key_4_b[i]).collect();
        assert!(
            untouched.is_empty(),
            "expected all 8 words of round_key[4] to differ, but words {untouched:?} matched — key schedule diffusion regression?"
        );
    }

    #[test]
    fn single_bit_key_difference_gives_near_50_percent_bit_avalanche() {
        // Более точная проверка, чем просто assert_ne! — считаем реальное
        // число отличающихся бит в позднем раундовом ключе и проверяем,
        // что оно близко к идеальным 50% (128 из 256), а не просто "не ноль".
        let key_a: State = [0; WORDS];
        let mut key_b: State = [0; WORDS];
        key_b[3] = 1 << 15; // бит в середине слова[3], для разнообразия

        let sched_a = expand_key(key_a);
        let sched_b = expand_key(key_b);

        let last_a = sched_a.0[ROUNDS];
        let last_b = sched_b.0[ROUNDS];

        let diff_bits: u32 = (0..WORDS).map(|i| (last_a[i] ^ last_b[i]).count_ones()).sum();
        // Допуск ±40 бит вокруг идеальных 128 — статистика на одном
        // фиксированном входе шумная, это smoke-test, не строгий SAC-тест
        // (для строгой статистики см. analysis/avalanche_test.py).
        assert!(
            (88..=168).contains(&diff_bits),
            "expected near-50% avalanche in final round key, got {diff_bits}/256 differing bits"
        );
    }
}