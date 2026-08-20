# Skhoron-Quark

> ⚠️ **Экспериментальный криптографический примитив. НЕ для продакшена.**
> См. [`docs/DISCLAIMER.md`](docs/DISCLAIMER.md).
> Для реальной защиты данных используйте AES-256-GCM или
> XChaCha20-Poly1305 (RustCrypto: `aes-gcm`, `chacha20poly1305`).

ARX-based (Addition-Rotation-XOR) экспериментальный блочный шифр, 256-бит
блок и ключ, без S-box. Исследовательский/учебный проект в экосистеме
[Skhoron](https://github.com/Skhoron), опубликованный открыто с первого
дня по принципу Керкгоффса — не скрывая конструкцию до "готовности".

Обоснование каждого решения — в [`docs/DESIGN_RATIONALE.md`](docs/DESIGN_RATIONALE.md).

## Структура репозитория

| Крейт | Назначение |
|---|---|
| `quark-core` | Сам блочный шифр: round-function, key schedule, encrypt/decrypt блока |
| `quark-aead` | Аутентифицированное шифрование поверх ядра: CTR-режим + BLAKE3 MAC, nonce |
| `quark-kdf` | Argon2id + HKDF: вывод ключей из пароля пользователя, domain separation |
| `quark-keygen` | Генерация случайного 256-бит ключа напрямую через OS CSPRNG |
| `quark-integration-tests` | Сквозные тесты полного пайплайна (пароль → ключ → AEAD) |
| `quark-file` | CLI: реальное шифрование/расшифровка файлов через Quark (пароль → Argon2id/HKDF → ключ → AEAD → файл на диске) |
| `analysis/` | Python-скрипты криптоанализа (branch number, avalanche, заготовка под SAT/MILP) — не часть шифра |
| `docs/` | Design rationale и дисклеймер |

## Быстрый старт

### Шифрование файла через CLI

```bash
cargo run --release -p skhoron-quark-file -- encrypt secret.txt secret.txt.skhq
cargo run --release -p skhoron-quark-file -- decrypt secret.txt.skhq secret_restored.txt
```

Формат `.skhq`: magic bytes + версия + соль (Argon2id) + nonce + шифротекст+MAC.
Подробности — `quark-file/src/format.rs`.

### Использование как библиотеки

```rust
use skhoron_quark_core::QuarkKey;
use skhoron_quark_aead::{QuarkAead, generate_nonce};
use skhoron_quark_keygen::generate_key;

// 1. Случайный ключ (или см. quark-kdf для вывода из пароля)
let key_bytes = generate_key();

// 2. AEAD-шифрование
let aead = QuarkAead::new(*key_bytes);
let nonce = generate_nonce();
let ciphertext = aead.encrypt(&nonce, b"hello, quark", b"");
let plaintext = aead.decrypt(&nonce, &ciphertext, b"").unwrap();
assert_eq!(plaintext, b"hello, quark");
```

## Сборка и тесты

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

> Код в этом репозитории не был скомпилирован в среде, где он был
> написан (нет доступа к сети для загрузки крейтов) — соберите и
> прогоните тесты локально перед использованием. Один тест
> (`test_vectors.rs`) содержит placeholder, который нужно заполнить
> реальным значением при первом успешном запуске — инструкция в самом файле.

## Статус конструкции

- **Avalanche проверен практически**: изначальная 3-слойная схема
  (Sum→Cross-XOR→Rotation) имела структурный изъян — слова с нечётным
  индексом не смешивались с частью остальных слов ни при каком числе
  раундов. Найдено через `analysis/avalanche_test.py`, исправлено
  добавлением Permutation-layer. Подробности и цифры — `docs/DESIGN_RATIONALE.md`
  §2.1. После фикса ~128/256 бит меняются уже к 6-8 раунду.
- Ротационные константы и число раундов (`quark-core/src/constants.rs`) —
  **предварительные**, не прошли формальный дифференциальный/линейный анализ
  (в отличие от avalanche — это про статистику на случайных входах, а
  differential cryptanalysis ищет специально подобранные "плохие" входы).
- Key schedule — не анализировался на related-key атаки.
- См. чеклист открытых задач в конце `docs/DESIGN_RATIONALE.md`.

## Лицензия

Apache License 2.0 — см. [`LICENSE`](LICENSE).

## Contributing

См. [`CONTRIBUTING.md`](CONTRIBUTING.md).