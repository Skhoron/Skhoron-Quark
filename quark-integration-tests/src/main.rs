//! # Skhoron-Quark File Encryption CLI
//!
//! ⚠️ ЭКСПЕРИМЕНТАЛЬНО. Реально шифрует и расшифровывает файлы через
//! Quark AEAD. Сам шифр не прошёл независимый криптоанализ — см.
//! корневой `docs/DISCLAIMER.md`.
//!
//! ## Известное архитектурное ограничение (см. README/ревью)
//!
//! Весь входной файл читается в память целиком (`fs::read`), как и весь
//! выходной буфер перед записью. Для больших файлов это означает
//! пропорционально большое потребление RAM (несколько копий данных
//! одновременно) и потенциальный OOM на очень больших файлах. Потоковое
//! (chunked) шифрование — открытая задача, не реализовано в этой версии
//! (см. DESIGN_RATIONALE.md).

mod format;

use clap::{Parser, Subcommand};
use format::{build_file, parse_file, NONCE_LEN, SALT_LEN};
use rand::{rngs::OsRng, RngCore};
use skhoron_quark_aead::QuarkAead;
use skhoron_quark_kdf::SkhoronKdf;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

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
    Encrypt {
        input: PathBuf,
        output: PathBuf,
        /// Перезаписать output, если файл уже существует. Без этого
        /// флага — ошибка, если файл на месте (защита от случайной
        /// потери данных из-за опечатки в имени файла).
        #[arg(long)]
        force: bool,
    },
    Decrypt {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

fn read_password(prompt: &str) -> String {
    print!("{prompt}");
    use std::io::Write as _;
    std::io::stdout().flush().ok();
    rpassword::read_password().unwrap_or_default()
}

fn derive_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let kdf = SkhoronKdf::default_params();
    let master = kdf
        .derive_master_secret(password, salt)
        .expect("argon2id derivation failed");
    let key_bytes = master
        .derive_subkey(b"skhoron-quark-file:encryption-key-v1", 32)
        .expect("hkdf expand failed");
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&key_bytes);
    key
}

fn print_disclaimer() {
    eprintln!("⚠️  Skhoron-Quark — экспериментальный шифр, не прошёл независимый аудит.");
    eprintln!("    Не используйте для защиты реальных секретов. Продолжаю по вашему запросу.\n");
}

/// Проверяет, что output можно безопасно создать: либо файла нет, либо
/// передан `--force`. Раньше `fs::write` молча перезаписывал существующий
/// файл — опечатка в пути output могла уничтожить данные без предупреждения.
fn check_output_allowed(output: &Path, force: bool) -> Result<(), String> {
    if output.exists() && !force {
        return Err(format!(
            "Файл {output:?} уже существует. Используйте --force, чтобы перезаписать."
        ));
    }
    Ok(())
}

/// Атомарная запись: временный файл рядом с целевым → fsync → rename.
/// Защищает от повреждённого выходного файла при сбое/обрыве питания
/// посреди записи (раньше — прямой `fs::write`, без этой гарантии).
fn write_atomic(output: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp_path = output.with_extension("tmp");
    {
        let mut tmp_file = fs::File::create(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?;
    }
    fs::rename(&tmp_path, output)?;
    Ok(())
}

fn main() {
    print_disclaimer();
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { input, output, force } => {
            if let Err(e) = check_output_allowed(&output, force) {
                eprintln!("{e}");
                std::process::exit(1);
            }

            // Zeroizing<Vec<u8>>: обычный fs::read даёт Vec<u8>, который
            // не зануляется при Drop — оборачиваем сразу, чтобы plaintext
            // не оставался в памяти дольше необходимого (было замечание
            // в ревью: "plaintext после обработки не очищается").
            let plaintext: Zeroizing<Vec<u8>> = match fs::read(&input) {
                Ok(data) => Zeroizing::new(data),
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

            let aead = QuarkAead::new(*key);

            // AAD = заголовок формата (magic+version+salt+nonce) — теперь
            // криптографически привязан к шифротексту через MAC. Раньше
            // AAD была пустой; magic/version и так проверялись парсером
            // при разборе файла, но привязка через AAD — более строгая
            // гарантия (любое изменение заголовка теперь ломает
            // аутентификацию, а не только парсинг).
            let mut header_for_aad = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN);
            header_for_aad.extend_from_slice(format::MAGIC);
            header_for_aad.push(format::VERSION);
            header_for_aad.extend_from_slice(&salt);
            header_for_aad.extend_from_slice(&nonce);

            let ciphertext_and_tag = match aead.encrypt_with_nonce(&nonce, &plaintext, &header_for_aad) {
                Ok(ct) => ct,
                Err(e) => {
                    eprintln!("Ошибка шифрования: {e}");
                    std::process::exit(1);
                }
            };

            let file_bytes = build_file(&salt, &nonce, &ciphertext_and_tag);

            if let Err(e) = write_atomic(&output, &file_bytes) {
                eprintln!("Не удалось записать {output:?}: {e}");
                std::process::exit(1);
            }

            println!("Зашифровано: {input:?} -> {output:?} ({} байт)", file_bytes.len());
        }

        Command::Decrypt { input, output, force } => {
            if let Err(e) = check_output_allowed(&output, force) {
                eprintln!("{e}");
                std::process::exit(1);
            }

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

            let aead = QuarkAead::new(*key);

            // header_bytes уже включает salt+nonce из самого файла — та же
            // AAD, что использовалась при шифровании (см. encrypt выше).
            match aead.decrypt_with_nonce(&parsed.nonce, parsed.ciphertext_and_tag, parsed.header_bytes) {
                Ok(plaintext) => {
                    let plaintext = Zeroizing::new(plaintext);
                    if let Err(e) = write_atomic(&output, &plaintext) {
                        eprintln!("Не удалось записать {output:?}: {e}");
                        std::process::exit(1);
                    }
                    println!("Расшифровано: {input:?} -> {output:?} ({} байт)", plaintext.len());
                }
                Err(e) => {
                    eprintln!(
                        "Ошибка расшифровки: {e}\n\
                         Возможные причины: неверный пароль, повреждённый файл, \
                         или файл был изменён после шифрования."
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}