//! # Skhoron-Quark AEAD
//!
//! ⚠️ ЭКСПЕРИМЕНТАЛЬНО. Не для продакшена — см. skhoron-quark-core.
//!
//! Аутентифицированное шифрование поверх блочного шифра Skhoron-Quark:
//!   - Режим шифрования: CTR-подобный (nonce || counter шифруется блоком
//!     как keystream, XOR с plaintext) — не требует padding, plaintext
//!     любой длины.
//!   - Аутентификация: BLAKE3 keyed hash над (nonce || ciphertext),
//!     encrypt-then-MAC (сначала шифруем, потом считаем MAC от шифротекста —
//!     так атакующий не может подделать valid-looking ciphertext без
//!     доступа к MAC-ключу, и MAC проверяется до попытки расшифровать).
//!   - Ключ для шифрования и ключ для MAC выводятся из одного мастер-ключа
//!     через `blake3::derive_key` с разными context-строками (domain
//!     separation) — компрометация одного не раскрывает другой.
//!
//! Аналог по назначению — XChaCha20-Poly1305, но построен на
//! экспериментальном примитиве Quark вместо ChaCha20/Poly1305.

pub mod nonce;

use nonce::NONCE_LEN;
use skhoron_quark_core::{QuarkKey, BLOCK_SIZE_BYTES};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

pub use nonce::generate_nonce;

const MAC_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum QuarkAeadError {
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("invalid nonce length: expected {NONCE_LEN} bytes, got {0}")]
    InvalidNonceLength(usize),
    #[error("authentication failed: ciphertext or associated data was modified, or wrong key")]
    AuthenticationFailed,
    #[error("ciphertext too short to contain a valid MAC tag")]
    CiphertextTooShort,
}

/// Аутентифицированный шифр Skhoron-Quark.
pub struct QuarkAead {
    enc_key: QuarkKey,
    mac_key: [u8; 32],
}

impl QuarkAead {
    /// Создаёт QuarkAead из 32-байтного мастер-ключа.
    /// Внутри выводит отдельные подключи для шифрования и MAC через
    /// `blake3::derive_key` с domain-separated context-строками.
    pub fn new(master_key: [u8; 32]) -> Self {
        let enc_key_bytes: [u8; 32] = blake3::derive_key("skhoron-quark-aead:encryption-key-v1", &master_key);
        let mac_key: [u8; 32] = blake3::derive_key("skhoron-quark-aead:mac-key-v1", &master_key);

        Self {
            enc_key: QuarkKey::new(enc_key_bytes),
            mac_key,
        }
    }

    /// Шифрует `plaintext` с уникальным `nonce` (24 байта, генерировать
    /// через `generate_nonce()`, никогда не переиспользовать с тем же ключом).
    /// `associated_data` — опциональные данные, которые аутентифицируются,
    /// но не шифруются (например, заголовок сообщения).
    ///
    /// Возвращает `nonce || ciphertext || mac_tag`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        let ciphertext = self.apply_keystream(nonce, plaintext);

        let mut mac_input = Vec::with_capacity(NONCE_LEN + associated_data.len() + ciphertext.len() + 8);
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(&(associated_data.len() as u64).to_le_bytes());
        mac_input.extend_from_slice(associated_data);
        mac_input.extend_from_slice(&ciphertext);

        let tag = blake3::keyed_hash(&self.mac_key, &mac_input);

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len() + MAC_LEN);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(tag.as_bytes());
        out
    }

    /// Расшифровывает данные, полученные из `encrypt` (без nonce — nonce
    /// передаётся отдельно, тем же значением, что использовалось при шифровании).
    /// Проверяет MAC ДО расшифровки (encrypt-then-MAC), в constant time.
    pub fn decrypt(
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

        // Constant-time сравнение — критично, чтобы не давать атакующему
        // timing-оракул через ранний return при первом несовпадающем байте.
        if expected_tag.as_bytes().ct_eq(received_tag).unwrap_u8() != 1 {
            return Err(QuarkAeadError::AuthenticationFailed);
        }

        Ok(self.apply_keystream(nonce, ciphertext))
    }

    /// CTR-подобный keystream: шифрует блоки (nonce || counter) и XOR'ит
    /// с данными. Один и тот же метод используется и для encrypt, и для
    /// decrypt — XOR с одним и тем же keystream самообратен.
    fn apply_keystream(&self, nonce: &[u8; NONCE_LEN], data: &[u8]) -> Vec<u8> {
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

            counter = counter.wrapping_add(1);
        }

        out
    }
}

impl Drop for QuarkAead {
    fn drop(&mut self) {
        self.mac_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let aead = QuarkAead::new([0x42; 32]);
        let nonce = generate_nonce();
        let plaintext = b"Skhoron Quark experimental cipher - roundtrip test message that spans more than one block.";

        let ciphertext = aead.encrypt(&nonce, plaintext, b"");
        let decrypted = aead.decrypt(&nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let aead = QuarkAead::new([0x42; 32]);
        let nonce = generate_nonce();
        let plaintext = b"secret message";

        let mut ciphertext = aead.encrypt(&nonce, plaintext, b"");
        ciphertext[0] ^= 0x01; // портим один бит

        let result = aead.decrypt(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_associated_data_fails_authentication() {
        let aead = QuarkAead::new([0x42; 32]);
        let nonce = generate_nonce();
        let plaintext = b"secret message";

        let ciphertext = aead.encrypt(&nonce, plaintext, b"header-v1");
        let result = aead.decrypt(&nonce, &ciphertext, b"header-v2");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let aead_a = QuarkAead::new([0x01; 32]);
        let aead_b = QuarkAead::new([0x02; 32]);
        let nonce = generate_nonce();

        let ciphertext = aead_a.encrypt(&nonce, b"data", b"");
        let result = aead_b.decrypt(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(QuarkAeadError::AuthenticationFailed)));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let aead = QuarkAead::new([0x99; 32]);
        let nonce = generate_nonce();
        let ciphertext = aead.encrypt(&nonce, b"", b"");
        let decrypted = aead.decrypt(&nonce, &ciphertext, b"").unwrap();
        assert!(decrypted.is_empty());
    }
}