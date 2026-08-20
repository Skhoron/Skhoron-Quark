//! # Skhoron-Quark File Encryption CLI
//!
//! ⚠️ ЭКСПЕРИМЕНТАЛЬНО. Реально шифрует и расшифровывает файлы через
//! Quark AEAD — это НЕ демонстрация "понарошку", это настоящее
//! шифрование/расшифровка. Но сам шифр (`quark-core`/`quark-aead`) не
//! прошёл независимый криптоанализ — см. корневой `docs/DISCLAIMER.md`.
//!
//! Ключ выводится из пароля пользователя через Argon2id + HKDF
//! (crate `skhoron-quark-kdf`) — единственные крипто-примитивы здесь,
//! которые НЕ написаны самостоятельно (Argon2id, HKDF, сам RNG).
//! Всё остальное — round-function, key schedule, AEAD-режим, формат
//! файла — код Skhoron-Quark.

mod format;

use clap::{Parser, Subcommand};
use format::{build_file, parse_file, NONCE_LEN, SALT_LEN};
use rand::{rngs::OsRng, RngCore};
use skhoron_quark_aead::QuarkAead;
use skhoron_quark_kdf::SkhoronKdf;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "skhoron-quark-file",
    about = "Шифрование/расшифровка файлов экспериментальным шифром Skhoron-Quark. НЕ для реальных секретов — см. DISCLAIMER.md"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Зашифровать файл.
    Encrypt {
        input: PathBuf,
        output: PathBuf,
    },
    /// Расшифровать файл.
    Decrypt {
        input: PathBuf,
        output: PathBuf,
    },
}

fn read_password(prompt: &str) -> String {
    print!("{prompt}");
    use std::io::Write;
    std::io::stdout().flush().ok();
    rpassword::read_password().unwrap_or_default()
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let kdf = SkhoronKdf::default_params();
    let master = kdf
        .derive_master_secret(password, salt)
        .expect("argon2id derivation failed");
    let key_bytes = master
        .derive_subkey(b"skhoron-quark-file:encryption-key-v1", 32)
        .expect("hkdf expand failed");
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    key
}

fn print_disclaimer() {
    eprintln!("⚠️  Skhoron-Quark — экспериментальный шифр, не прошёл независимый аудит.");
    eprintln!("    Не используйте для защиты реальных секретов. Продолжаю по вашему запросу.\n");
}

fn main() {
    print_disclaimer();
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { input, output } => {
            let plaintext = match fs::read(&input) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Не удалось прочитать {input:?}: {e}");
                    std::process::exit(1);
                }
            };

            let mut password = read_password("Пароль для шифрования: ");
            let confirm = read_password("Повторите пароль: ");
            if password != confirm {
                eprintln!("Пароли не совпадают.");
                password.zeroize();
                std::process::exit(1);
            }

            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let mut nonce = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce);

            let key = derive_key(&password, &salt);
            password.zeroize();

            let aead = QuarkAead::new(key);
            // Associated data пустая — привязка к оригинальному имени файла
            // здесь не делается специально: при decrypt пользователь обычно
            // указывает путь к .skhq-файлу, а не к исходному файлу, так что
            // использование пути как AD давало бы почти гарантированный
            // mismatch между encrypt/decrypt. Если нужна защита от
            // переименования/подмены файла, добавьте отдельное поле
            // "original filename" в заголовок формата (format.rs) и
            // используйте его как AD на обеих сторонах явно.
            let ciphertext_and_tag = aead.encrypt(&nonce, &plaintext, b"");

            let file_bytes = build_file(&salt, &nonce, &ciphertext_and_tag);

            if let Err(e) = fs::write(&output, &file_bytes) {
                eprintln!("Не удалось записать {output:?}: {e}");
                std::process::exit(1);
            }

            println!("Зашифровано: {input:?} -> {output:?} ({} байт)", file_bytes.len());
        }

        Command::Decrypt { input, output } => {
            let file_bytes = match fs::read(&input) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Не удалось прочитать {input:?}: {e}");
                    std::process::exit(1);
                }
            };

            let parsed = match parse_file(&file_bytes) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Ошибка формата файла: {e}");
                    std::process::exit(1);
                }
            };

            let mut password = read_password("Пароль для расшифровки: ");
            let key = derive_key(&password, parsed.salt);
            password.zeroize();

            let aead = QuarkAead::new(key);
            match aead.decrypt(&parsed.nonce, parsed.ciphertext_and_tag, b"") {
                Ok(plaintext) => {
                    if let Err(e) = fs::write(&output, &plaintext) {
                        eprintln!("Не удалось записать {output:?}: {e}");
                        std::process::exit(1);
                    }
                    println!("Расшифровано: {input:?} -> {output:?} ({} байт)", plaintext.len());
                }
                Err(e) => {
                    eprintln!(
                        "Ошибка расшифровки: {e}\n\
                         Возможные причины: неверный пароль или повреждённый файл."
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}