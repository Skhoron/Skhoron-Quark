#!/usr/bin/env python3
"""
Проверка branch number для round-function Skhoron-Quark.

Branch number — минимальное количество активных S-box'ов/слов, которое
гарантированно "зацепит" однобитное (или произвольное ненулевое) изменение
входа после прохождения слоя диффузии. Чем выше branch number, тем быстрее
растёт число активных слов по раундам — а значит быстрее падает вероятность
успешной дифференциальной атаки.

Этот скрипт НЕ заменяет формальный дифференциальный анализ (см.
differential_search.py — там заготовка под SAT/MILP поиск). Он даёт
быструю практическую оценку: для случайных ненулевых входных разностей
считаем, сколько слов состояния отличается после N раундов round-function,
и строим гистограмму.

Требует: ничего, кроме стандартной библиотеки Python.
Запуск: python3 branch_number.py
"""

import random

WORDS = 8
MASK32 = 0xFFFFFFFF
ROTATIONS = [7, 13, 17, 23, 3, 29, 11, 19]  # должно совпадать с constants.rs


def rotl32(x: int, r: int) -> int:
    r %= 32
    return ((x << r) | (x >> (32 - r))) & MASK32


def sum_layer(state):
    s = state[:]
    s[0] = (s[0] + s[1]) & MASK32
    s[2] = (s[2] + s[3]) & MASK32
    s[4] = (s[4] + s[5]) & MASK32
    s[6] = (s[6] + s[7]) & MASK32
    return s


def cross_xor_layer(state):
    s = state[:]
    s[6] ^= s[0]
    s[4] ^= s[6]
    s[2] ^= s[4]
    s[0] ^= s[2]
    return s


def rotation_layer(state):
    return [rotl32(state[i], ROTATIONS[i]) for i in range(WORDS)]


def permutation_layer(state):
    """Циклический сдвиг массива слов на 1 позиция — см. round.rs за
    обоснование, почему этот слой обязателен (без него слова 1,3,5,7
    никогда не смешиваются друг с другом)."""
    return state[1:] + state[:1]


def forward_round(state):
    state = sum_layer(state)
    state = cross_xor_layer(state)
    state = rotation_layer(state)
    state = permutation_layer(state)
    return state


def hamming_weight_words(a, b):
    """Сколько слов отличается между двумя состояниями."""
    return sum(1 for x, y in zip(a, b) if x != y)


def hamming_weight_bits(a, b):
    return sum(bin((x ^ y) & MASK32).count("1") for x, y in zip(a, b))


def random_state():
    return [random.getrandbits(32) for _ in range(WORDS)]


def flip_random_bit(state):
    s = state[:]
    word_idx = random.randrange(WORDS)
    bit_idx = random.randrange(32)
    s[word_idx] ^= (1 << bit_idx)
    return s


def run_experiment(num_rounds: int, num_trials: int = 5000):
    word_diffs = []
    bit_diffs = []

    for _ in range(num_trials):
        base = random_state()
        flipped = flip_random_bit(base)

        a, b = base, flipped
        for _ in range(num_rounds):
            a = forward_round(a)
            b = forward_round(b)

        word_diffs.append(hamming_weight_words(a, b))
        bit_diffs.append(hamming_weight_bits(a, b))

    avg_word_diff = sum(word_diffs) / len(word_diffs)
    avg_bit_diff = sum(bit_diffs) / len(bit_diffs)
    min_word_diff = min(word_diffs)

    print(f"Раундов: {num_rounds}")
    print(f"  Среднее число отличающихся слов (из {WORDS}):  {avg_word_diff:.2f}")
    print(f"  Минимальное число отличающихся слов:           {min_word_diff}")
    print(f"  Среднее число отличающихся бит (из {WORDS*32}): {avg_bit_diff:.2f} "
          f"(идеал ~{WORDS*32/2:.0f} при полном avalanche)")
    print()


if __name__ == "__main__":
    print("=== Skhoron-Quark: практическая проверка branch number / avalanche ===")
    print("(быстрая оценка, НЕ формальное доказательство стойкости)\n")
    for rounds in [1, 2, 3, 4, 6, 8, 12, 16, 24]:
        run_experiment(rounds)