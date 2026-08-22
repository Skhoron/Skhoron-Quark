//! Локальное хранилище хешей паролей: простой файл вида
//! `label:phc_hash_string` построчно.
//!
//! ⚠️ Файл хранит PHC-хеши (Argon2id), НЕ сами пароли — безопасно
//! хранить открытым текстом (как /etc/shadow). Labels хранятся открытым
//! текстом — если нужна конфиденциальность и меток, шифруйте файл целиком
//! отдельным слоем (не реализовано здесь намеренно).

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Максимальная длина label в байтах — защита от случайного/враждебного
/// ввода (например, огромной строки или бинарных данных под видом label).
pub const MAX_LABEL_LENGTH: usize = 128;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed line in store file: {0:?}")]
    MalformedLine(String),
    #[error("label {0:?} not found in store")]
    LabelNotFound(String),
    #[error("label {0:?} already exists — use a different label or remove the old one first")]
    LabelAlreadyExists(String),
    #[error("duplicate label {0:?} found in store file — file may be corrupted or manually edited incorrectly")]
    DuplicateLabelInFile(String),
    #[error("label is empty")]
    EmptyLabel,
    #[error("label {0:?} exceeds maximum length of {MAX_LABEL_LENGTH} bytes")]
    LabelTooLong(String),
    #[error("label {0:?} contains a forbidden character (':', newline, or carriage return)")]
    LabelContainsForbiddenChar(String),
}

/// Валидирует label: непустой, не длиннее MAX_LABEL_LENGTH, не содержит
/// ':' (используется как разделитель формата), '\n' или '\r' (сломали бы
/// построчный формат файла).
fn validate_label(label: &str) -> Result<(), StoreError> {
    if label.is_empty() {
        return Err(StoreError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LENGTH {
        return Err(StoreError::LabelTooLong(label.to_string()));
    }
    if label.contains(':') || label.contains('\n') || label.contains('\r') {
        return Err(StoreError::LabelContainsForbiddenChar(label.to_string()));
    }
    Ok(())
}

pub struct PasswordStore {
    entries: HashMap<String, String>, // label -> PHC hash string
    path: PathBuf,
}

impl PasswordStore {
    /// Загружает хранилище из файла, если он существует, иначе создаёт пустое.
    /// Обнаруживает дублирующиеся labels в файле как ошибку (раньше
    /// последняя запись молча перезаписывала предыдущие с тем же label —
    /// это могло маскировать повреждение файла или ручную правку с ошибкой).
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let mut entries = HashMap::new();

        if path.exists() {
            let content = fs::read_to_string(&path)?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (label, hash) = line
                    .split_once(':')
                    .ok_or_else(|| StoreError::MalformedLine(line.to_string()))?;

                if entries.contains_key(label) {
                    return Err(StoreError::DuplicateLabelInFile(label.to_string()));
                }
                entries.insert(label.to_string(), hash.to_string());
            }
        }

        Ok(Self { entries, path })
    }

    pub fn add(&mut self, label: &str, phc_hash: &str) -> Result<(), StoreError> {
        validate_label(label)?;
        if self.entries.contains_key(label) {
            return Err(StoreError::LabelAlreadyExists(label.to_string()));
        }
        self.entries.insert(label.to_string(), phc_hash.to_string());
        self.persist()
    }

    pub fn get(&self, label: &str) -> Result<&str, StoreError> {
        self.entries
            .get(label)
            .map(|s| s.as_str())
            .ok_or_else(|| StoreError::LabelNotFound(label.to_string()))
    }

    pub fn remove(&mut self, label: &str) -> Result<(), StoreError> {
        if self.entries.remove(label).is_none() {
            return Err(StoreError::LabelNotFound(label.to_string()));
        }
        self.persist()
    }

    pub fn list_labels(&self) -> Vec<&str> {
        let mut labels: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        labels.sort_unstable();
        labels
    }

    /// Атомарная запись: пишем во временный файл рядом с целевым, делаем
    /// fsync, затем rename поверх целевого файла. `rename` на одной
    /// файловой системе — атомарная операция на уровне ОС: либо виден
    /// старый файл целиком, либо новый целиком, никогда промежуточное
    /// состояние. Это защищает от повреждения store при сбое/обрыве
    /// питания посреди записи (что было бы возможно с прямым `fs::write`).
    ///
    /// На Unix дополнительно выставляет права доступа 0600 (только
    /// владелец может читать/писать) — файл содержит Argon2id-хеши и
    /// labels, не должен быть доступен другим локальным пользователям.
    fn persist(&self) -> Result<(), StoreError> {
        let mut content = String::new();
        content.push_str("# Skhoron-Passgen store — labels + Argon2id PHC hashes.\n");
        content.push_str("# НЕ содержит сами пароли, только их хеши.\n");
        let mut labels: Vec<&String> = self.entries.keys().collect();
        labels.sort_unstable();
        for label in labels {
            content.push_str(label);
            content.push(':');
            content.push_str(&self.entries[label]);
            content.push('\n');
        }

        let tmp_path = self.path.with_extension("tmp");
        {
            let mut tmp_file = fs::File::create(&tmp_path)?;
            tmp_file.write_all(content.as_bytes())?;
            tmp_file.sync_all()?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = tmp_file.metadata()?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&tmp_path, perms)?;
            }
        }
        fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn add_get_remove_roundtrip() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        std::fs::remove_file(path).ok();

        let mut store = PasswordStore::load_or_create(path).unwrap();
        store.add("example.com", "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA").unwrap();

        assert_eq!(
            store.get("example.com").unwrap(),
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA"
        );

        store.remove("example.com").unwrap();
        assert!(matches!(store.get("example.com"), Err(StoreError::LabelNotFound(_))));
    }

    #[test]
    fn persists_across_reload() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        {
            let mut store = PasswordStore::load_or_create(&path).unwrap();
            store.add("service-a", "hash-a-placeholder").unwrap();
        }

        let store2 = PasswordStore::load_or_create(&path).unwrap();
        assert_eq!(store2.get("service-a").unwrap(), "hash-a-placeholder");
    }

    #[test]
    fn rejects_duplicate_label_on_add() {
        let file = NamedTempFile::new().unwrap();
        let mut store = PasswordStore::load_or_create(file.path()).unwrap();
        store.add("dup", "hash1").unwrap();
        assert!(matches!(store.add("dup", "hash2"), Err(StoreError::LabelAlreadyExists(_))));
    }

    #[test]
    fn rejects_duplicate_label_found_in_file_on_load() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        fs::write(&path, "github.com:hash1\ngithub.com:hash2\n").unwrap();

        let result = PasswordStore::load_or_create(&path);
        assert!(matches!(result, Err(StoreError::DuplicateLabelInFile(_))));
    }

    #[test]
    fn rejects_empty_label() {
        let file = NamedTempFile::new().unwrap();
        let mut store = PasswordStore::load_or_create(file.path()).unwrap();
        assert!(matches!(store.add("", "hash"), Err(StoreError::EmptyLabel)));
    }

    #[test]
    fn rejects_label_with_colon() {
        let file = NamedTempFile::new().unwrap();
        let mut store = PasswordStore::load_or_create(file.path()).unwrap();
        assert!(matches!(
            store.add("bad:label", "hash"),
            Err(StoreError::LabelContainsForbiddenChar(_))
        ));
    }

    #[test]
    fn rejects_label_with_newline() {
        let file = NamedTempFile::new().unwrap();
        let mut store = PasswordStore::load_or_create(file.path()).unwrap();
        assert!(matches!(
            store.add("bad\nlabel", "hash"),
            Err(StoreError::LabelContainsForbiddenChar(_))
        ));
    }

    #[test]
    fn rejects_label_too_long() {
        let file = NamedTempFile::new().unwrap();
        let mut store = PasswordStore::load_or_create(file.path()).unwrap();
        let long_label = "a".repeat(MAX_LABEL_LENGTH + 1);
        assert!(matches!(store.add(&long_label, "hash"), Err(StoreError::LabelTooLong(_))));
    }

    #[test]
    fn rejects_malformed_line_without_colon() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        fs::write(&path, "this line has no colon separator\n").unwrap();
        assert!(matches!(PasswordStore::load_or_create(&path), Err(StoreError::MalformedLine(_))));
    }

    #[cfg(unix)]
    #[test]
    fn store_file_has_restrictive_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let mut store = PasswordStore::load_or_create(&path).unwrap();
        store.add("test", "hash").unwrap();

        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}