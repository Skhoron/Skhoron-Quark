//! Интеграционные тесты: проверяют публичный API как внешний пользователь
//! библиотеки, без доступа к внутренним модулям.
//!
//! NB: этот файл лежит в tests/ на верхнем уровне репозитория как общий
//! integration-suite. Он собирается отдельным Cargo target'ом и требует
//! добавления зависимостей ниже в [dev-dependencies] соответствующего
//! крейта, либо оформления как отдельный workspace member с тестами
//! (см. README про запуск `cargo test --workspace`).

use skhoron_quark_aead::{generate_nonce, QuarkAead};
use skhoron_quark_core::QuarkKey;
use skhoron_quark_keygen::generate_key;
use skhoron_quark_kdf::SkhoronKdf;

#[test]
fn full_pipeline_password_to_encrypted_message() {
    // 1. Пользователь вводит пароль -> Argon2id -> мастер-секрет -> подключ шифрования
    let kdf = SkhoronKdf::default_params();
    let salt = b"unique-per-user-salt-16bytes!!!";
    let master = kdf.derive_master_secret("correct horse battery staple", salt).unwrap();
    let enc_key: [u8; 32] = master
        .derive_subkey(b"skhoron-quark:example-message-key", 32)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

    // 2. AEAD-шифрование сообщения этим ключом
    let aead = QuarkAead::new(enc_key);
    let nonce = generate_nonce();
    let plaintext = b"integration test across the full Skhoron-Quark pipeline";

    let ciphertext = aead.encrypt(&nonce, plaintext, b"");
    let decrypted = aead.decrypt(&nonce, &ciphertext, b"").unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn keygen_produces_usable_block_cipher_key() {
    let key_bytes = generate_key();
    let key = QuarkKey::new(*key_bytes);

    let plaintext = [0xAAu8; 32];
    let ciphertext = key.encrypt_block(&plaintext);
    let decrypted = key.decrypt_block(&ciphertext);

    assert_eq!(decrypted, plaintext);
}