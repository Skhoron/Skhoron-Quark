#!/usr/bin/env python3
"""
Статистический avalanche-тест для полного блочного шифра Skhoron-Quark
(round-function + key schedule + все раунды), в отличие от branch_number.py,
который проверяет только round-function отдельно.

Строгий Strict Avalanche Criterion (SAC): при изменении одного входного
бита (plaintext ИЛИ ключа) каждый выходной бит должен меняться с
вероятностью ~50%, независимо от того, какой именно бит был изменён.

Это тоже практическая/статистическая проверка, не формальное доказательство.
Требует: ничего, кроме стандартной библиотеки Python (полная реализация
шифра продублирована на Python для независимости от Rust-сборки — так
скрипт можно гонять без `cargo build`, что важно в окружениях без сети).

Запуск: python3 avalanche_test.py
"""

import random

WORDS = 8
MASK32 = 0xFFFFFFFF
ROTATIONS = [7, 13, 17, 23, 3, 29, 11, 19]
ROUNDS = 24
KEY_SCHEDULE_INCREMENT = 0x9E3779B9


def rotl32(x, r):
    r %= 32
    return ((x << r) | (x >> (32 - r))) & MASK32


def sum_layer(s):
    s = s[:]
    s[0] = (s[0] + s[1]) & MASK32
    s[2] = (s[2] + s[3]) & MASK32
    s[4] = (s[4] + s[5]) & MASK32
    s[6] = (s[6] + s[7]) & MASK32
    return s


def cross_xor_layer(s):
    s = s[:]
    s[6] ^= s[0]
    s[4] ^= s[6]
    s[2] ^= s[4]
    s[0] ^= s[2]
    return s


def rotation_layer(s):
    return [rotl32(s[i], ROTATIONS[i]) for i in range(WORDS)]


def permutation_layer(s):
    return s[1:] + s[:1]


def forward_round(s):
    return permutation_layer(rotation_layer(cross_xor_layer(sum_layer(s))))


def expand_key(master_key):
    state = master_key[:]
    c = KEY_SCHEDULE_INCREMENT
    round_keys = []
    for _ in range(ROUNDS + 1):
        state = [state[j] ^ ((c * (j + 1)) & MASK32) for j in range(WORDS)]
        state = forward_round(state)
        round_keys.append(state[:])
        c = (c + KEY_SCHEDULE_INCREMENT) & MASK32
    return round_keys


def encrypt_block(master_key, plaintext_words):
    round_keys = expand_key(master_key)
    state = plaintext_words[:]
    for r in range(ROUNDS):
        state = [state[i] ^ round_keys[r][i] for i in range(WORDS)]
        state = forward_round(state)
    state = [state[i] ^ round_keys[ROUNDS][i] for i in range(WORDS)]
    return state


def random_words(n=WORDS):
    return [random.getrandbits(32) for _ in range(n)]


def flip_bit(words, word_idx, bit_idx):
    w = words[:]
    w[word_idx] ^= (1 << bit_idx)
    return w


def hamming_distance_words(a, b):
    return sum(bin((x ^ y) & MASK32).count("1") for x, y in zip(a, b))


def sac_test_plaintext_bits(num_trials=200):
    """Меняем случайный бит plaintext, ключ фиксирован per trial."""
    total_bits = WORDS * 32
    diffs = []
    for _ in range(num_trials):
        key = random_words()
        pt = random_words()
        word_idx = random.randrange(WORDS)
        bit_idx = random.randrange(32)
        pt2 = flip_bit(pt, word_idx, bit_idx)

        ct1 = encrypt_block(key, pt)
        ct2 = encrypt_block(key, pt2)
        diffs.append(hamming_distance_words(ct1, ct2))

    avg = sum(diffs) / len(diffs)
    print(f"[SAC / plaintext bit flip] среднее число отличающихся бит: "
          f"{avg:.2f} из {total_bits} (идеал: {total_bits/2:.0f}, т.е. 50%)")


def sac_test_key_bits(num_trials=200):
    """Меняем случайный бит ключа, plaintext фиксирован per trial."""
    total_bits = WORDS * 32
    diffs = []
    for _ in range(num_trials):
        key = random_words()
        pt = random_words()
        word_idx = random.randrange(WORDS)
        bit_idx = random.randrange(32)
        key2 = flip_bit(key, word_idx, bit_idx)

        ct1 = encrypt_block(key, pt)
        ct2 = encrypt_block(key2, pt)
        diffs.append(hamming_distance_words(ct1, ct2))

    avg = sum(diffs) / len(diffs)
    print(f"[SAC / key bit flip]       среднее число отличающихся бит: "
          f"{avg:.2f} из {total_bits} (идеал: {total_bits/2:.0f}, т.е. 50%)")


if __name__ == "__main__":
    print("=== Skhoron-Quark: Strict Avalanche Criterion, полный шифр, "
          f"{ROUNDS} раундов ===\n")
    print("(независимая Python-реализация, статистическая проверка, "
          "не формальное доказательство)\n")
    sac_test_plaintext_bits()
    sac_test_key_bits()