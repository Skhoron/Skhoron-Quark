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

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("file too short to contain a valid header")]
    TooShort,
    #[error("invalid magic bytes — this is not a Skhoron-Quark encrypted file")]
    InvalidMagic,
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),
}

pub struct ParsedHeader<'a> {
    pub salt: &'a [u8],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext_and_tag: &'a [u8],
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

    Ok(ParsedHeader {
        salt,
        nonce,
        ciphertext_and_tag,
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
}