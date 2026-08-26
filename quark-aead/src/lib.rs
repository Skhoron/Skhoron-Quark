//! # Skhoron-Quark AEAD
//!
//! ⚠️ ЭКСПЕРИМЕНТАЛЬНО. Не для продакшена — см. skhoron-quark-core.
//!
//! Аутентифицированное шифрование поверх блочного шифра Skhoron-Quark:
//!   - Режим шифрования: CTR-подобный (nonce || counter шифруется блоком
//!     как keystream, XOR с plaintext).
//!   - Аутентификация: BLAKE3 keyed hash над (nonce || AD || ciphertext),
//!     encrypt-then-MAC.
//!   - Ключи шифрования и MAC разделены через `blake3::derive_key`.
//!
//! ## Изменение API (по итогам ревью)
//!
//! Раньше `encrypt()` встраивал nonce в возвращаемый буфер
//! (`nonce || ciphertext || tag`), а `decrypt()` при этом ожидал на вход
//! ЧИСТЫЙ `ciphertext || tag` (без nonce) плюс nonce отдельным аргументом.
//! Это асимметрично и провоцирует ошибку использования: любой код, который
//! наивно передавал результат `encrypt()` напрямую в `decrypt()` (как
//! делал `quark-file`), получал на вход лишние 24 байта nonce внутри
//! "ciphertext", из-за чего MAC не совпадал НИКОГДА — расшифровка была
//! гарантированно сломана. Обнаружено и подтверждено при разборе ревью.
//!
//! Теперь:
//!   - `encrypt_with_nonce`/`decrypt_with_nonce` — низкоуровневый API,
//!     симметричный: оба принимают nonce отдельно, оба оперируют ЧИСТЫМ
//!     `ciphertext || tag` без embedded nonce. Для вызывающего кода,
//!     который сам управляет хранением nonce (как `quark-file`, у
//!     которого nonce уже есть в заголовке формата файла).
//!   - `encrypt`/`decrypt` — высокоуровневый безопасный API: `encrypt`
//!     сам генерирует nonce через OsRng и возвращает его вместе с
//!     результатом — невозможно случайно передать один и тот же nonce
//!     дважды, как было возможно при прямом использовании `generate_nonce()`
//!     отдельно от `encrypt()`.

pub mod nonce;

use nonce::NONCE_LEN;
use rand::{rngs::OsRng, RngCore};
use skhoron_quark_core::{QuarkKey, BLOCK_SIZE_BYTES};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub use nonce::generate_nonce;

const MAC_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum QuarkAeadError {
    #[error("authentication failed: ciphertext or associated data was modified, or wrong key")]
    AuthenticationFailed,
    #[error("ciphertext too short to contain a valid MAC tag")]
    CiphertextTooShort,
    #[error(
        "keystream counter exhausted (2^64 blocks encrypted with one nonce) — \
         this would require encrypting over 2^64 * 32 bytes with a single nonce; \
         generate a new nonce instead of continuing"
    )]
    CounterExhausted,
}

/// Аутентифицированный шифр Skhoron-Quark.
pub struct QuarkAead {
    enc_key: QuarkKey,
    /// Обёрнут в `Zeroizing` (было исправлено — раньше был обычный
    /// `[u8; 32]` с ручным zeroize только в `Drop` этой структуры).
    /// `Zeroizing` даёт ту же гарантию декларативно на уровне типа —
    /// защита от будущего рефакторинга, который может случайно убрать
    /// или сломать ручную реализацию `Drop`.
    mac_key: Zeroizing<[u8; 32]>,
}

impl QuarkAead {
    pub fn new(mut master_key: [u8; 32]) -> Self {
        let enc_key_bytes: [u8; 32] = blake3::derive_key("skhoron-quark-aead:encryption-key-v1", &master_key);
        let mac_key: [u8; 32] = blake3::derive_key("skhoron-quark-aead:mac-key-v1", &master_key);

        // Явный zeroize входного master_key (было исправлено — раньше
        // параметр функции не зачищался явно и полагался на то, что
        // стековая память будет переиспользована естественным образом,
        // без явной гарантии).
        master_key.zeroize();

        Self {
            enc_key: QuarkKey::new(enc_key_bytes),
            mac_key: Zeroizing::new(mac_key),
        }
    }

    /// Высокоуровневый безопасный API: генерирует nonce сам, возвращает
    /// его вместе с шифротекстом. Использовать по умолчанию — нельзя
    /// случайно переиспользовать nonce, потому что вызывающий код никогда
    /// не выбирает его сам.
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
        let nonce = generate_nonce();
        let ciphertext_and_tag = self
            .encrypt_with_nonce(&nonce, plaintext, associated_data)
            .expect("fresh OsRng-generated nonce cannot exhaust the counter");
        (nonce, ciphertext_and_tag)
    }

    /// Высокоуровневый API расшифровки, симметричный `encrypt`.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext_and_tag: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, QuarkAeadError> {
        self.decrypt_with_nonce(nonce, ciphertext_and_tag, associated_data)
    }

    /// Низкоуровневый API: nonce передаётся явно вызывающим кодом.
    /// ⚠️ Вызывающий код ОБЯЗАН гарантировать, что nonce никогда не
    /// повторяется для одного и того же ключа. Возвращает ТОЛЬКО
    /// `ciphertext || tag`, БЕЗ embedded nonce (в отличие от старой версии).
    pub fn encrypt_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, QuarkAeadError> {
        let ciphertext = self.apply_keystream(nonce, plaintext)?;

        let mut mac_input = Vec::with_capacity(NONCE_LEN + associated_data.len() + ciphertext.len() + 8);
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(&(associated_data.len() as u64).to_le_bytes());
        mac_input.extend_from_slice(associated_data);
        mac_input.extend_from_slice(&ciphertext);

        let tag = blake3::keyed_hash(&self.mac_key, &mac_input);

        let mut out = Vec::with_capacity(ciphertext.len() + MAC_LEN);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(tag.as_bytes());
        Ok(out)
    }

    /// Низкоуровневый API расшифровки, симметричный `encrypt_with_nonce`.
    /// Проверяет MAC ДО расшифровки (encrypt-then-MAC), в constant time.
    pub fn decrypt_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext_and_tag: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, QuarkAeadError> {
        if ciphertext_and_tag.len() < MAC_LEN {
            return Err(QuarkAeadError::CiphertextTooShort);
        }
        let split_at = ciphertext_and_tag.len() - MAC_LEN;
        let ciphertext = &ciphertext_and_tag[..split_at];
        let received_tag = &ciphertext_and_tag[split_at..];

        let mut mac_input = Vec::with_capacity(NONCE_LEN + associated_data.len() + ciphertext.len() + 8);
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(&(associated_data.len() as u64).to_le_bytes());
        mac_input.extend_from_slice(associated_data);
        mac_input.extend_from_slice(ciphertext);

        let expected_tag = blake3::keyed_hash(&self.mac_key, &mac_input);

        if expected_tag.as_bytes().ct_eq(received_tag).unwrap_u8() != 1 {
            return Err(QuarkAeadError::AuthenticationFailed);
        }

        self.apply_keystream(nonce, ciphertext)
    }

    /// CTR-подобный keystream. Возвращает ошибку `CounterExhausted` вместо
    /// молчаливого переполнения `counter` через `wrapping_add` (как было
    /// раньше) — переполнение counter означало бы повторное использование
    /// того же keystream-блока при том же nonce, что ломает
    /// конфиденциальность. Практически недостижимо (нужно 2^64 блоков =
    /// огромный объём данных на один nonce), но семантика API должна быть
    /// явной, а не полагаться на то, что до переполнения "реально никто
    /// не дойдёт".
    fn apply_keystream(&self, nonce: &[u8; NONCE_LEN], data: &[u8]) -> Result<Vec<u8>, QuarkAeadError> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter: u64 = 0;

        for chunk in data.chunks(BLOCK_SIZE_BYTES) {
            let mut counter_block = [0u8; BLOCK_SIZE_BYTES];
            counter_block[..NONCE_LEN].copy_from_slice(nonce);
            counter_block[NONCE_LEN..].copy_from_slice(&counter.to_le_bytes());

            let keystream = self.enc_key.encrypt_block(&counter_block);

            for (i, byte) in chunk.iter().enumerate() {
                out.push(byte ^ keystream[i]);
            }

            counter = counter.checked_add(1).ok_or(QuarkAeadError::CounterExhausted)?;
        }

        Ok(out)
    }
}

// Ручной `impl Drop` больше не нужен — `Zeroizing<[u8; 32]>` уже
// зануляет память самостоятельно при выходе `mac_key` из scope
// (было исправлено — раньше был ручной Drop, дублирующий то, что теперь
// гарантирует сам тип).

/// Плейнтекст/шифротекст, автоматически зануляемый при выходе из scope.
/// Вспомогательный тип для вызывающего кода, который хочет гарантировать
/// очистку буфера (например, quark-file для расшифрованных данных перед
/// записью на диск).
pub type SensitiveBytes = Zeroizing<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_level_encrypt_decrypt_roundtrip() {
        let aead = QuarkAead::new([0x42; 32]);
        let plaintext = b"Skhoron Quark experimental cipher - roundtrip test message.";

        let (nonce, ciphertext) = aead.encrypt(plaintext, b"");
        let decrypted = aead.decrypt(&nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn low_level_encrypt_decrypt_roundtrip_matches_high_level() {
        // Регрессионный тест на найденный баг: раньше encrypt_with_nonce
        // (тогда просто "encrypt") встраивал nonce в результат, а
        // decrypt_with_nonce (тогда "decrypt") этого не ожидал — что
        // ломало любой код, передающий вывод encrypt напрямую в decrypt
        // с тем же nonce отдельным аргументом (именно так делал quark-file).
        let aead = QuarkAead::new([0x77; 32]);
        let nonce = generate_nonce();
        let plaintext = b"low level api test message spanning more than one block of data";

        let ciphertext_and_tag = aead.encrypt_with_nonce(&nonce, plaintext, b"").unwrap();
        let decrypted = aead.decrypt_with_nonce(&nonce, &ciphertext_and_tag, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let aead = QuarkAead::new([0x42; 32]);
        let (nonce, mut ciphertext) = aead.encrypt(b"secret message", b"");
        ciphertext[0] ^= 0x01;

        let result = aead.decrypt(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_associated_data_fails_authentication() {
        let aead = QuarkAead::new([0x42; 32]);
        let (nonce, ciphertext) = aead.encrypt(b"secret message", b"header-v1");
        let result = aead.decrypt(&nonce, &ciphertext, b"header-v2");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let aead_a = QuarkAead::new([0x01; 32]);
        let aead_b = QuarkAead::new([0x02; 32]);

        let (nonce, ciphertext) = aead_a.encrypt(b"data", b"");
        let result = aead_b.decrypt(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let aead = QuarkAead::new([0x99; 32]);
        let (nonce, ciphertext) = aead.encrypt(b"", b"");
        let decrypted = aead.decrypt(&nonce, &ciphertext, b"").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn two_high_level_encrypt_calls_use_different_nonces() {
        // Гарантия, которую даёт новый безопасный API: nonce генерируется
        // внутри, вызывающий код не может случайно передать одно и то же
        // значение дважды (как было возможно со старым API).
        let aead = QuarkAead::new([0x11; 32]);
        let (nonce_a, _) = aead.encrypt(b"message one", b"");
        let (nonce_b, _) = aead.encrypt(b"message two", b"");
        assert_ne!(nonce_a, nonce_b);
    }

    #[test]
    fn bit_flip_in_nonce_fails_authentication() {
        // Регрессия на #11 из ревью: hostile-input тест на nonce.
        let aead = QuarkAead::new([0x33; 32]);
        let (mut nonce, ciphertext) = aead.encrypt(b"data", b"");
        nonce[0] ^= 0x01;
        let result = aead.decrypt(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn truncated_ciphertext_at_various_lengths_never_panics() {
        // Регрессия на #11: усечение на каждой длине не должно паниковать,
        // только возвращать ошибку.
        let aead = QuarkAead::new([0x44; 32]);
        let (nonce, ciphertext) = aead.encrypt(b"some plaintext data for truncation testing", b"");

        for len in 0..ciphertext.len() {
            let truncated = &ciphertext[..len];
            let result = aead.decrypt(&nonce, truncated, b"");
            assert!(result.is_err(), "truncated ciphertext of length {len} must not decrypt successfully");
        }
    }

    #[test]
    fn empty_ciphertext_is_rejected_not_panicking() {
        let aead = QuarkAead::new([0x55; 32]);
        let nonce = generate_nonce();
        let result = aead.decrypt(&nonce, b"", b"");
        assert!(matches!(result, Err(QuarkAeadError::CiphertextTooShort)));
    }

    #[test]
    fn bit_flip_in_mac_tag_fails_authentication() {
        let aead = QuarkAead::new([0x66; 32]);
        let (nonce, mut ciphertext) = aead.encrypt(b"data", b"");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        let result = aead.decrypt(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }
}