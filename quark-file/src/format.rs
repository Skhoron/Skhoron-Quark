//! Формат `.skhq` файла — свой формат, не крипто-примитив, просто
//! структура байт на диске.
//!
//! ```text
//! [0..4)   magic bytes: b"SKQF"
//! [4)      version byte: 0x01
//! [5..21)  Argon2id salt (16 bytes)
//! [21..45) AEAD nonce (24 bytes)
//! [45..)   ciphertext || MAC tag (из quark-aead, tag — последние 32 байта)
//! ```
//!
//! Соль и nonce хранятся открытым текстом в заголовке — это стандартная,
//! безопасная практика (соль/nonce не секретны сами по себе, секретен
//! только пароль/ключ).

use thiserror::Error;

pub const MAGIC: &[u8; 4] = b"SKQF";
pub const VERSION: u8 = 0x01;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
/// Длина MAC-тега (BLAKE3 keyed hash, см. `quark-aead`). Дублируется здесь
/// (не импортируется из quark-aead, где это приватная константа) —
/// используется только для ранней валидации длины тела файла на уровне
/// формата, а не для крипто-операций.
const MAC_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("file too short to contain a valid header")]
    TooShort,
    #[error("invalid magic bytes — this is not a Skhoron-Quark encrypted file")]
    InvalidMagic,
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),
    #[error("file body ({0} bytes) is shorter than the minimum possible ciphertext+MAC tag ({MAC_LEN} bytes) — file is truncated or corrupted")]
    BodyTooShort(usize),
}

pub struct ParsedHeader<'a> {
    pub salt: &'a [u8],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext_and_tag: &'a [u8],
    /// Байты заголовка (magic+version+salt+nonce) — используются как
    /// associated data при AEAD, чтобы magic/version/salt были
    /// криптографически привязаны к шифротексту (см. header_bytes ниже
    /// и правку в main.rs — раньше AAD была пустой, и заголовок можно
    /// было подменить без падения аутентификации, хотя изменение magic/
    /// version и так ловилось парсером формата, отдельной атаки это не
    /// давало, но привязка через AAD — более строгая гарантия целостности).
    pub header_bytes: &'a [u8],
}

/// Собирает заголовок + шифротекст в один буфер для записи на диск.
pub fn build_file(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN], ciphertext_and_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext_and_tag.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext_and_tag);
    out
}

/// Разбирает файл на заголовок и тело.
pub fn parse_file(data: &[u8]) -> Result<ParsedHeader<'_>, FormatError> {
    if data.len() < HEADER_LEN {
        return Err(FormatError::TooShort);
    }
    if &data[0..4] != MAGIC {
        return Err(FormatError::InvalidMagic);
    }
    let version = data[4];
    if version != VERSION {
        return Err(FormatError::UnsupportedVersion(version));
    }

    let salt = &data[5..5 + SALT_LEN];
    let nonce_start = 5 + SALT_LEN;
    let nonce_end = nonce_start + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[nonce_start..nonce_end]);

    let ciphertext_and_tag = &data[nonce_end..];
    if ciphertext_and_tag.len() < MAC_LEN {
        return Err(FormatError::BodyTooShort(ciphertext_and_tag.len()));
    }
    let header_bytes = &data[0..nonce_end];

    Ok(ParsedHeader {
        salt,
        nonce,
        ciphertext_and_tag,
        header_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let salt = [0x11u8; SALT_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let body = b"fake ciphertext and tag bytes here";

        let file_bytes = build_file(&salt, &nonce, body);
        let parsed = parse_file(&file_bytes).unwrap();

        assert_eq!(parsed.salt, &salt);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.ciphertext_and_tag, body);
        assert_eq!(parsed.header_bytes.len(), HEADER_LEN);
        assert_eq!(&parsed.header_bytes[0..4], MAGIC);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut file_bytes = build_file(&[0u8; SALT_LEN], &[0u8; NONCE_LEN], b"x");
        file_bytes[0] = b'X';
        assert!(matches!(parse_file(&file_bytes), Err(FormatError::InvalidMagic)));
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(parse_file(b"short"), Err(FormatError::TooShort)));
    }

    #[test]
    fn rejects_body_shorter_than_mac_len() {
        // Регрессия на #6 из ревью: раньше parse_file() не проверял, что
        // тело после заголовка достаточно длинное для валидного MAC-тега —
        // ошибка ловилась только позже, внутри quark-aead::decrypt.
        // Теперь формат отклоняет заведомо повреждённый контейнер раньше.
        let file_bytes = build_file(&[0u8; SALT_LEN], &[0u8; NONCE_LEN], b"short_body");
        let result = parse_file(&file_bytes);
        assert!(matches!(result, Err(FormatError::BodyTooShort(_))));
    }

    #[test]
    fn accepts_body_exactly_mac_len() {
        // Граничный случай: тело ровно MAC_LEN байт (пустой ciphertext,
        // только tag) — валидный минимальный контейнер, должен парситься.
        let body = vec![0u8; MAC_LEN];
        let file_bytes = build_file(&[0u8; SALT_LEN], &[0u8; NONCE_LEN], &body);
        assert!(parse_file(&file_bytes).is_ok());
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut file_bytes = build_file(&[0u8; SALT_LEN], &[0u8; NONCE_LEN], &vec![0u8; MAC_LEN]);
        file_bytes[4] = 0xFF; // versiоn byte
        assert!(matches!(parse_file(&file_bytes), Err(FormatError::UnsupportedVersion(0xFF))));
    }

    #[test]
    fn header_bytes_change_when_salt_or_nonce_changes() {
        // header_bytes используется как AAD в quark-file — проверяем, что
        // он реально зависит от salt/nonce (а не случайно фиксирован).
        let file_a = build_file(&[0x01u8; SALT_LEN], &[0x02u8; NONCE_LEN], &vec![0u8; MAC_LEN]);
        let file_b = build_file(&[0x03u8; SALT_LEN], &[0x02u8; NONCE_LEN], &vec![0u8; MAC_LEN]);
        let parsed_a = parse_file(&file_a).unwrap();
        let parsed_b = parse_file(&file_b).unwrap();
        assert_ne!(parsed_a.header_bytes, parsed_b.header_bytes);
    }
}