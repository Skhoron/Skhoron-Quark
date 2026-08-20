//! Round-function Skhoron-Quark: три слоя на 8 слов состояния (256 бит).
//!
//! Каждый раунд состоит из трёх слоёв, применяемых последовательно:
//!   1. Sum layer      — единственная нелинейная операция (modular addition),
//!                        даёт устойчивость к линейному криптоанализу.
//!   2. Cross-XOR layer — цепочка XOR между парами слов, обеспечивает
//!                        диффузию между "половинами" состояния.
//!   3. Rotation layer  — побитовая ротация каждого слова на свою константу,
//!                        обеспечивает диффузию внутри слова (avalanche).
//!
//! Все три слоя обратимы по отдельности, поэтому обратимо и их сочетание —
//! `inverse_round` отменяет `forward_round`, применяя обратные операции
//! в обратном порядке.

use crate::constants::{ROTATIONS, WORDS};

pub type State = [u32; WORDS];

/// Sum layer (прямое направление).
/// Пары (0,1), (2,3), (4,5), (6,7): state[i] = state[i] + state[i+1] (mod 2^32).
/// state[i+1] остаётся неизменным — это и делает слой обратимым.
#[inline]
fn sum_layer(state: &mut State) {
    state[0] = state[0].wrapping_add(state[1]);
    state[2] = state[2].wrapping_add(state[3]);
    state[4] = state[4].wrapping_add(state[5]);
    state[6] = state[6].wrapping_add(state[7]);
}

/// Обратный Sum layer: state[i] = state[i] - state[i+1] (mod 2^32).
#[inline]
fn inverse_sum_layer(state: &mut State) {
    state[0] = state[0].wrapping_sub(state[1]);
    state[2] = state[2].wrapping_sub(state[3]);
    state[4] = state[4].wrapping_sub(state[5]);
    state[6] = state[6].wrapping_sub(state[7]);
}

/// Cross-XOR layer (прямое направление).
/// Последовательная цепочка: каждый шаг использует уже обновлённое на
/// предыдущем шаге значение — это создаёт каскадную диффузию (похоже на
/// то, как ChaCha цепочкой обновляет слова внутри quarter-round).
///
/// Порядок шагов:
///   state[6] ^= state[0]
///   state[4] ^= state[6]   (использует новое state[6])
///   state[2] ^= state[4]   (использует новое state[4])
///   state[0] ^= state[2]   (использует новое state[2])
#[inline]
fn cross_xor_layer(state: &mut State) {
    state[6] ^= state[0];
    state[4] ^= state[6];
    state[2] ^= state[4];
    state[0] ^= state[2];
}

/// Обратный Cross-XOR layer: те же операции в обратном порядке.
/// XOR самообратен, а обратный порядок гарантирует, что на каждом шаге
/// "другой операнд" имеет то же значение, что и при прямом проходе.
#[inline]
fn inverse_cross_xor_layer(state: &mut State) {
    state[0] ^= state[2];
    state[2] ^= state[4];
    state[4] ^= state[6];
    state[6] ^= state[0];
}

/// Rotation layer: каждое слово вращается влево на свою константу из ROTATIONS.
#[inline]
fn rotation_layer(state: &mut State) {
    for i in 0..WORDS {
        state[i] = state[i].rotate_left(ROTATIONS[i]);
    }
}

/// Обратный Rotation layer: вращение вправо на ту же константу.
#[inline]
fn inverse_rotation_layer(state: &mut State) {
    for i in 0..WORDS {
        state[i] = state[i].rotate_right(ROTATIONS[i]);
    }
}

/// Permutation layer: циклический сдвиг МАССИВА слов на 1 позицию.
///
/// ⚠️ КРИТИЧЕСКИ ВАЖНЫЙ слой, добавлен после того, как практический
/// avalanche-тест (analysis/avalanche_test.py) показал структурный
/// изъян исходной трёхслойной схемы: Sum-layer навсегда фиксирует пары
/// (0,1),(2,3),(4,5),(6,7) — слово с нечётным индексом мешается только
/// со своим фиксированным партнёром и никогда не достигает остальных
/// нечётных слов, даже после 24 раундов (проверено экспериментально —
/// флип бита в слове[1] не долетал до слов[3],[5],[7] вообще).
///
/// Без смены пар между раундами часть состояния остаётся структурно
/// изолированной вне зависимости от количества раундов — это не
/// исправляется увеличением ROUNDS, потому что проблема в топологии
/// связей, а не в их количестве повторений.
///
/// Циклический сдвиг на 1 гарантирует, что каждое слово со временем
/// проходит через все 8 позиций и оказывается в паре со всеми
/// остальными словами не позднее чем через WORDS-1 = 7 раундов.
#[inline]
fn permutation_layer(state: &mut State) {
    state.rotate_left(1);
}

/// Обратный Permutation layer.
#[inline]
fn inverse_permutation_layer(state: &mut State) {
    state.rotate_right(1);
}

/// Один полный раунд шифрования: Sum -> Cross-XOR -> Rotation -> Permutation.
#[inline]
pub fn forward_round(state: &mut State) {
    sum_layer(state);
    cross_xor_layer(state);
    rotation_layer(state);
    permutation_layer(state);
}

/// Один полный раунд расшифрования: отменяет forward_round.
/// Порядок слоёв обратный: Permutation^-1 -> Rotation^-1 -> Cross-XOR^-1 -> Sum^-1.
#[inline]
pub fn inverse_round(state: &mut State) {
    inverse_permutation_layer(state);
    inverse_rotation_layer(state);
    inverse_cross_xor_layer(state);
    inverse_sum_layer(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_is_invertible() {
        let original: State = [
            0x1234_5678, 0x9ABC_DEF0, 0x0F0F_0F0F, 0xF0F0_F0F0, 0xDEAD_BEEF, 0xCAFE_BABE,
            0x1111_2222, 0x3333_4444,
        ];
        let mut state = original;
        forward_round(&mut state);
        assert_ne!(state, original, "round must change the state");
        inverse_round(&mut state);
        assert_eq!(state, original, "inverse_round must undo forward_round exactly");
    }

    #[test]
    fn round_is_invertible_across_many_random_states() {
        // Детерминированный псевдослучайный набор состояний (не крипто-RNG,
        // тест не требует крипто-стойкой случайности, только покрытие).
        let mut seed: u64 = 0x243F_6A88_85A3_08D3;
        for _ in 0..1000 {
            let mut original: State = [0; WORDS];
            for w in original.iter_mut() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *w = seed as u32;
            }
            let mut state = original;
            forward_round(&mut state);
            inverse_round(&mut state);
            assert_eq!(state, original);
        }
    }

    #[test]
    fn single_bit_flip_changes_many_bits_after_several_rounds() {
        let base: State = [0; WORDS];
        let mut flipped: State = [0; WORDS];
        flipped[0] = 1; // один бит отличается

        let mut a = base;
        let mut b = flipped;
        for _ in 0..8 {
            forward_round(&mut a);
            forward_round(&mut b);
        }

        let mut diff_bits = 0u32;
        for i in 0..WORDS {
            diff_bits += (a[i] ^ b[i]).count_ones();
        }
        // По результатам analysis/avalanche_test.py полный avalanche
        // (~128 из 256 бит) достигается к 6-8 раунду благодаря
        // permutation_layer (см. DESIGN_RATIONALE.md, раздел 2.1 —
        // без него часть слов не смешивалась вообще ни при каком числе
        // раундов). Здесь проверяем разумный нижний порог, не точное
        // значение — статистика на одном фиксированном входе шумная.
        assert!(
            diff_bits > 80,
            "expected near-full avalanche after 8 rounds, got {diff_bits}/256 differing bits"
        );
    }

    #[test]
    fn permutation_layer_reaches_all_words_within_word_count_rounds() {
        // Регрессионный тест на найденный и исправленный структурный изъян:
        // без permutation_layer флип бита в odd-indexed слове никогда не
        // достигал некоторых других слов, независимо от числа раундов.
        // Проверяем, что после WORDS раундов (достаточно для полного
        // цикла циклического сдвига) возмущение долетает до всех 8 слов.
        let base: State = [0; WORDS];
        let mut flipped: State = [0; WORDS];
        flipped[1] = 1; // намеренно odd-indexed слово — именно оно было изолировано

        let mut a = base;
        let mut b = flipped;
        for _ in 0..WORDS {
            forward_round(&mut a);
            forward_round(&mut b);
        }

        let untouched: Vec<usize> = (0..WORDS).filter(|&i| a[i] == b[i]).collect();
        assert!(
            untouched.is_empty(),
            "expected all words to be affected after {WORDS} rounds, but words {untouched:?} were untouched — permutation_layer regression?"
        );
    }
}