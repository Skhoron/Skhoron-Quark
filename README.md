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

# Перезаписать существующий output-файл нужно явно:
cargo run --release -p skhoron-quark-file -- encrypt secret.txt secret.txt.skhq --force
```

Формат `.skhq`: magic bytes + версия + соль (Argon2id) + nonce + шифротекст+MAC.
Подробности — `quark-file/src/format.rs`.

### Использование как библиотеки

```rust
use skhoron_quark_aead::QuarkAead;
use skhoron_quark_keygen::generate_key;

// 1. Случайный ключ (или см. quark-kdf для вывода из пароля)
let key_bytes = generate_key();

// 2. AEAD-шифрование — безопасный высокоуровневый API: nonce
//    генерируется автоматически внутри encrypt(), исключая случайное
//    повторное использование nonce вызывающим кодом.
let aead = QuarkAead::new(*key_bytes);
let (nonce, ciphertext) = aead.encrypt(b"hello, quark", b"");
let plaintext = aead.decrypt(&nonce, &ciphertext, b"").unwrap();
assert_eq!(plaintext, b"hello, quark");
```

Низкоуровневый API (`encrypt_with_nonce`/`decrypt_with_nonce`) доступен
для случаев, когда nonce нужно хранить/передавать отдельно (как делает
`quark-file` — nonce уже есть в заголовке `.skhq`-файла).

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

- **Avalanche в round-function** проверен практически: изначальная
  3-слойная схема имела структурный изъян (слова не смешивались
  полностью), исправлено добавлением Permutation-layer. См.
  `docs/DESIGN_RATIONALE.md` §2.1.
- **Key schedule** имел аналогичный изъян: разница в одном слове ключа
  не покидала это слово вплоть до 24 раунда. Исправлено переиспользованием
  `forward_round` вместо независимого обновления слов. См. §5.
- **AEAD API** содержал баг: `encrypt()`/`decrypt()` были асимметричны
  (embedded nonce), из-за чего расшифровка в `quark-file` была
  гарантированно сломана. Исправлено разделением на
  `encrypt`/`decrypt` (безопасный high-level) и
  `encrypt_with_nonce`/`decrypt_with_nonce` (low-level). См. §8.
- Ротационные константы и число раундов (24) — по-прежнему
  **предварительные**, не прошли формальный дифференциальный/линейный анализ.
- `quark-file` читает весь файл в память целиком — потоковое шифрование
  не реализовано, см. §9 открытых задач.
- См. полный список открытых задач в конце `docs/DESIGN_RATIONALE.md`.

## Лицензия

Apache License 2.0 — см. [`LICENSE`](LICENSE).

## Contributing

См. [`CONTRIBUTING.md`](CONTRIBUTING.md).