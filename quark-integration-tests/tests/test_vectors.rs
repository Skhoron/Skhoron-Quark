//! Known-answer tests (KAT).
//!
//! ⚠️ ВАЖНО про происхождение значений ниже: это НЕ "официальные" тестовые
//! векторы из внешнего источника (для нового экспериментального шифра их
//! просто не существует). Это self-consistency проверка: значение
//! `EXPECTED_CIPHERTEXT_HEX` было посчитано самим алгоритмом при
//! фиксированных ключе/plaintext и записано сюда, чтобы ловить
//! непреднамеренные изменения round-function/key-schedule в будущих
//! коммитах (например, если кто-то случайно поменяет порядок операций
//! в round.rs, этот тест сразу покажет расхождение).
//!
//! Собрать этот проект в текущем окружении (без доступа к сети для
//! скачивания крейтов) не удалось — при первом успешном `cargo test`
//! у себя нужно ЗАМЕНИТЬ placeholder ниже на реальное значение, которое
//! выведет тест через `println!` при первом запуске (см. код теста).

use skhoron_quark_core::QuarkKey;

#[test]
fn known_answer_vector_self_consistency() {
    let key = QuarkKey::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ]);
    let plaintext = [0u8; 32];

    let ciphertext = key.encrypt_block(&plaintext);
    let hex_output: String = ciphertext.iter().map(|b| format!("{b:02x}")).collect();

    // ЗАМЕНИТЬ после первого локального прогона:
    const EXPECTED_CIPHERTEXT_HEX_PLACEHOLDER: &str = "REPLACE_ME_AFTER_FIRST_LOCAL_RUN";

    if EXPECTED_CIPHERTEXT_HEX_PLACEHOLDER == "REPLACE_ME_AFTER_FIRST_LOCAL_RUN" {
        println!("KAT placeholder not yet filled. Computed ciphertext hex: {hex_output}");
        println!("Скопируйте эту строку в EXPECTED_CIPHERTEXT_HEX_PLACEHOLDER и уберите этот println-блок.");
    } else {
        assert_eq!(hex_output, EXPECTED_CIPHERTEXT_HEX_PLACEHOLDER);
    }

    // Базовая sanity-проверка работает уже сейчас, независимо от placeholder:
    let decrypted = key.decrypt_block(&ciphertext);
    assert_eq!(decrypted, plaintext);
}