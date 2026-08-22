//! Хеширование паролей: Argon2id (RFC 9106) через crate `argon2`.
//!
//! Сама хеш-функция — библиотечная. Наша часть — параметры, профили,
//! формат хранения, интеграция с остальным инструментом.

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("argon2 error: {0}")]
    Argon2(#[from] password_hash::Error),
    #[error("invalid argon2 parameters")]
    InvalidParams,
}

#[derive(Debug, Clone, Copy)]
pub struct HashParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl HashParams {
    /// Консервативный профиль для мобильных/слабых устройств —
    /// минимум, рекомендованный OWASP.
    pub fn mobile() -> Self {
        Self {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    /// Более требовательный профиль для десктопа/сервера, где память и
    /// CPU не так ограничены — выше сопротивление офлайн-перебору.
    pub fn desktop() -> Self {
        Self {
            memory_kib: 46 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl Default for HashParams {
    fn default() -> Self {
        Self::mobile()
    }
}

pub struct PasswordHasherWrapper {
    argon2: Argon2<'static>,
}

impl PasswordHasherWrapper {
    pub fn new(params: HashParams) -> Result<Self, HashError> {
        let argon2_params = Params::new(params.memory_kib, params.iterations, params.parallelism, None)
            .map_err(|_| HashError::InvalidParams)?;
        Ok(Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params),
        })
    }

    pub fn default_params() -> Self {
        Self::new(HashParams::default()).expect("default params are always valid")
    }

    /// Хеширует пароль, соль генерируется автоматически (OsRng).
    /// Возвращает PHC-строку — реальные параметры (m, t, p) записываются
    /// внутрь строки, поэтому `verify` всегда использует ТЕ параметры, с
    /// которыми хеш был создан, а не текущие default/desktop/mobile.
    pub fn hash(&self, password: &str) -> Result<String, HashError> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    /// Проверяет пароль против PHC-хеша. Constant-time сравнение
    /// обеспечивается самой crate `argon2`/`password-hash`.
    pub fn verify(&self, password: &str, stored_hash: &str) -> Result<bool, HashError> {
        let parsed = PasswordHash::new(stored_hash)?;
        Ok(self.argon2.verify_password(password.as_bytes(), &parsed).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hasher = PasswordHasherWrapper::default_params();
        let hash = hasher.hash("Tr0ub4dor&3xample").unwrap();
        assert!(hasher.verify("Tr0ub4dor&3xample", &hash).unwrap());
        assert!(!hasher.verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn same_password_produces_different_hashes_due_to_random_salt() {
        let hasher = PasswordHasherWrapper::default_params();
        let h1 = hasher.hash("same-password").unwrap();
        let h2 = hasher.hash("same-password").unwrap();
        assert_ne!(h1, h2, "different random salts must yield different PHC strings");
        assert!(hasher.verify("same-password", &h1).unwrap());
        assert!(hasher.verify("same-password", &h2).unwrap());
    }

    #[test]
    fn desktop_profile_verifies_correctly_with_its_own_params() {
        let hasher = PasswordHasherWrapper::new(HashParams::desktop()).unwrap();
        let hash = hasher.hash("desktop-profile-password").unwrap();
        assert!(hasher.verify("desktop-profile-password", &hash).unwrap());
    }

    #[test]
    fn verify_works_across_different_profile_instances_via_phc_params() {
        // Хешируем на desktop-профиле, но верифицируем через инстанс с
        // mobile-параметрами по умолчанию — должно сработать, потому что
        // verify_password берёт параметры ИЗ PHC-строки, а не из self.
        let desktop_hasher = PasswordHasherWrapper::new(HashParams::desktop()).unwrap();
        let mobile_hasher = PasswordHasherWrapper::default_params();

        let hash = desktop_hasher.hash("cross-profile-check").unwrap();
        assert!(mobile_hasher.verify("cross-profile-check", &hash).unwrap());
    }
}