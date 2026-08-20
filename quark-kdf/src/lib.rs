//! # Skhoron-Quark KDF
//!
//! Обёртка над Argon2id для превращения пароля пользователя в
//! криптографические ключи. Это НЕ новый примитив — вся стойкость
//! опирается на Argon2id (RFC 9106) и HKDF-SHA256 (RFC 5869), оба
//! проверенных стандартизированных алгоритма. Здесь только удобный
//! и безопасный API поверх них.
//!
//! Возможности:
//!   1. Domain-separated key derivation (HKDF поверх Argon2id-вывода) —
//!      из одного пароля выводятся НЕСКОЛЬКО независимых ключей для
//!      разных целей; утечка одного не раскрывает другие.
//!   2. Zeroize — все секреты стираются из памяти при выходе из scope.
//!   3. Опциональный pepper — секрет на стороне приложения (не в БД),
//!      добавляется к паролю перед Argon2id.
//!   4. CSPRNG-генератор паролей без modulo bias (rejection sampling).
//!   5. PHC-формат хранения хешей.
//!
//! Доработка относительно первой версии: `derive_key` больше не гоняет
//! Argon2id заново на каждый вызов. Вместо этого `DerivedMasterSecret`
//! считается ОДИН раз (дорогая операция), а последующие `derive_subkey`
//! вызовы — это только быстрый HKDF-expand с разными context-метками.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum SkhoronKdfError {
    #[error("argon2 hashing failed: {0}")]
    Argon2(#[from] password_hash::Error),
    #[error("hkdf expand failed (requested output too large)")]
    HkdfExpand,
    #[error("invalid parameter: {0}")]
    InvalidParam(&'static str),
}

/// Параметры Argon2id. Дефолты — минимум OWASP (m=19 MiB, t=2, p=1) для
/// мобильных устройств. Перед использованием в конкретном приложении
/// стоит замерить реальное время на целевом железе и при возможности
/// поднять memory_kib (например до 46*1024 на десктопе/сервере).
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
            output_len: 32,
        }
    }
}

pub struct SkhoronKdf {
    argon2: Argon2<'static>,
    params: KdfParams,
    /// Опциональный pepper — секрет приложения (НЕ хранится вместе с
    /// паролем/хешем в БД), добавляется к паролю перед Argon2id.
    /// Если None — pepper не используется (поведение как раньше).
    pepper: Option<Zeroizing<Vec<u8>>>,
}

impl SkhoronKdf {
    pub fn new(params: KdfParams) -> Result<Self, SkhoronKdfError> {
        let argon2_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(params.output_len),
        )
        .map_err(|_| SkhoronKdfError::InvalidParam("bad argon2 params"))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
        Ok(Self {
            argon2,
            params,
            pepper: None,
        })
    }

    pub fn default_params() -> Self {
        Self::new(KdfParams::default()).expect("default params are always valid")
    }

    /// Задаёт pepper — секрет приложения, хранящийся отдельно от БД
    /// (например, в переменной окружения или secure storage устройства).
    /// Компрометация одной только БД (без pepper) не позволяет восстановить
    /// пароли даже через словарную атаку на Argon2id-хеши.
    pub fn with_pepper(mut self, pepper: &[u8]) -> Self {
        self.pepper = Some(Zeroizing::new(pepper.to_vec()));
        self
    }

    fn peppered_password(&self, password: &str) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(password.len() + 32));
        buf.extend_from_slice(password.as_bytes());
        if let Some(pepper) = &self.pepper {
            buf.extend_from_slice(pepper);
        }
        buf
    }

    /// Хеширует пароль для хранения (например, мастер-пароль Skhoron Vault).
    /// Возвращает PHC-строку: $argon2id$v=19$m=...,t=...,p=...$salt$hash
    /// Соль генерируется автоматически из OsRng.
    pub fn hash_password(&self, password: &str) -> Result<String, SkhoronKdfError> {
        let salt = SaltString::generate(&mut OsRng);
        let peppered = self.peppered_password(password);
        let hash = self.argon2.hash_password(&peppered, &salt)?;
        Ok(hash.to_string())
    }

    /// Проверяет пароль против ранее сохранённого PHC-хеша.
    /// Constant-time сравнение обеспечивается самой password-hash crate.
    pub fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool, SkhoronKdfError> {
        let parsed_hash = PasswordHash::new(stored_hash)?;
        let peppered = self.peppered_password(password);
        Ok(self.argon2.verify_password(&peppered, &parsed_hash).is_ok())
    }

    /// Считает Argon2id ОДИН раз и возвращает держатель мастер-секрета,
    /// из которого можно быстро (без повторного Argon2id) вывести сколько
    /// угодно независимых подключей через `derive_subkey`.
    ///
    /// Используйте этот метод вместо повторных вызовов `derive_key`,
    /// если нужно несколько ключей из одного пароля — так Argon2id
    /// (дорогая операция) считается один раз за сессию, а не на каждый ключ.
    pub fn derive_master_secret(
        &self,
        password: &str,
        salt: &[u8],
    ) -> Result<DerivedMasterSecret, SkhoronKdfError> {
        let peppered = self.peppered_password(password);
        let mut secret = Zeroizing::new(vec![0u8; self.params.output_len]);
        self.argon2
            .hash_password_into(&peppered, salt, &mut secret)
            .map_err(SkhoronKdfError::Argon2)?;
        Ok(DerivedMasterSecret { secret })
    }

    /// Удобный метод "всё в одном": Argon2id + HKDF-expand за один вызов.
    /// Для НЕСКОЛЬКИХ ключей из одного пароля используйте
    /// `derive_master_secret` + `derive_subkey`, чтобы не пересчитывать
    /// Argon2id заново на каждый ключ.
    pub fn derive_key(
        &self,
        password: &str,
        salt: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SkhoronKdfError> {
        self.derive_master_secret(password, salt)?
            .derive_subkey(context, output_len)
    }
}

/// Мастер-секрет, полученный из пароля через Argon2id (дорогая операция,
/// посчитана один раз). Из него можно быстро вывести произвольное число
/// независимых подключей через `derive_subkey` (быстрый HKDF-expand).
pub struct DerivedMasterSecret {
    secret: Zeroizing<Vec<u8>>,
}

impl DerivedMasterSecret {
    /// Domain-separated вывод подключа: HKDF-expand с меткой `context`.
    ///
    /// Пример:
    ///   let master = kdf.derive_master_secret(pw, &salt)?;
    ///   let db_key    = master.derive_subkey(b"skhoron-vault:sqlcipher-key", 32)?;
    ///   let field_key = master.derive_subkey(b"skhoron-vault:field-encrypt", 32)?;
    /// Компрометация одного подключа не раскрывает другие и не раскрывает пароль.
    pub fn derive_subkey(&self, context: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>, SkhoronKdfError> {
        let hk = Hkdf::<Sha256>::new(None, &self.secret);
        let mut okm = Zeroizing::new(vec![0u8; output_len]);
        hk.expand(context, &mut okm)
            .map_err(|_| SkhoronKdfError::HkdfExpand)?;
        Ok(okm)
    }
}

/// Алфавиты для генератора паролей.
pub struct Charset;
impl Charset {
    pub const LOWER: &'static str = "abcdefghijklmnopqrstuvwxyz";
    pub const UPPER: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    pub const DIGITS: &'static str = "0123456789";
    pub const SYMBOLS: &'static str = "!@#$%^&*()-_=+[]{}";
    /// Похожие символы (0/O, 1/l/I) — исключаются по умолчанию для
    /// удобства ручного ввода/переписывания.
    pub const AMBIGUOUS: &'static str = "0O1lI";
}

/// Криптостойкий генератор паролей с защитой от modulo bias.
///
/// Наивный `OsRng.next_u32() % alphabet.len()` даёт смещённое
/// распределение символов — ослабляет энтропию незаметно для пользователя.
/// Здесь используется rejection sampling: значения, попадающие в
/// "неполный последний блок" диапазона, отбрасываются и генерируются заново.
pub fn generate_password(length: usize, alphabet: &str, exclude_ambiguous: bool) -> Result<String, SkhoronKdfError> {
    if length == 0 {
        return Err(SkhoronKdfError::InvalidParam("length must be > 0"));
    }

    let mut chars: Vec<char> = alphabet.chars().collect();
    if exclude_ambiguous {
        chars.retain(|c| !Charset::AMBIGUOUS.contains(*c));
    }
    if chars.is_empty() {
        return Err(SkhoronKdfError::InvalidParam("alphabet is empty after filtering"));
    }

    let n = chars.len() as u32;
    let limit = u32::MAX - (u32::MAX % n);

    let mut rng = OsRng;
    let mut password = String::with_capacity(length);

    while password.len() < length {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let val = u32::from_le_bytes(buf);
        buf.zeroize();

        if val >= limit {
            continue;
        }
        let idx = (val % n) as usize;
        password.push(chars[idx]);
    }

    Ok(password)
}

/// Пароль по умолчанию: буквы верхний/нижний регистр + цифры + символы,
/// 20 символов. Даёт ~131 бит энтропии (log2(94^20)).
pub fn generate_default_password() -> Result<String, SkhoronKdfError> {
    let alphabet = format!(
        "{}{}{}{}",
        Charset::LOWER,
        Charset::UPPER,
        Charset::DIGITS,
        Charset::SYMBOLS
    );
    generate_password(20, &alphabet, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let kdf = SkhoronKdf::default_params();
        let hash = kdf.hash_password("correct horse battery staple").unwrap();
        assert!(kdf.verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!kdf.verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn pepper_changes_the_hash() {
        let kdf_no_pepper = SkhoronKdf::default_params();
        let kdf_with_pepper = SkhoronKdf::default_params().with_pepper(b"app-secret-pepper");

        // Тот же salt намеренно не переиспользуется между реализациями —
        // тест проверяет, что verify с другим pepper-состоянием не проходит.
        let hash = kdf_with_pepper.hash_password("pw123").unwrap();
        assert!(kdf_with_pepper.verify_password("pw123", &hash).unwrap());
        assert!(!kdf_no_pepper.verify_password("pw123", &hash).unwrap());
    }

    #[test]
    fn derive_master_secret_and_subkeys_are_domain_separated() {
        let kdf = SkhoronKdf::default_params();
        let salt = b"fixed-salt-for-test-only-16b!!";

        let master1 = kdf.derive_master_secret("pw", salt).unwrap();
        let master2 = kdf.derive_master_secret("pw", salt).unwrap();

        let k1 = master1.derive_subkey(b"skhoron-vault:db", 32).unwrap();
        let k2 = master2.derive_subkey(b"skhoron-vault:db", 32).unwrap();
        let k3 = master1.derive_subkey(b"skhoron-vault:field", 32).unwrap();

        assert_eq!(&*k1, &*k2, "same password+salt+context must yield same key");
        assert_ne!(&*k1, &*k3, "different contexts must yield different keys");
    }

    #[test]
    fn generated_password_has_correct_length_and_charset() {
        let pw = generate_default_password().unwrap();
        assert_eq!(pw.len(), 20);
        let alphabet = format!("{}{}{}{}", Charset::LOWER, Charset::UPPER, Charset::DIGITS, Charset::SYMBOLS);
        assert!(pw.chars().all(|c| alphabet.contains(c)));
    }

    #[test]
    fn rejects_empty_length() {
        assert!(generate_password(0, Charset::LOWER, false).is_err());
    }
}