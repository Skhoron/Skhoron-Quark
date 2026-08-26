//! # Skhoron-Quark File Encryption CLI
//!
//! ⚠️ ЭКСПЕРИМЕНТАЛЬНО. Реально шифрует и расшифровывает файлы через
//! Quark AEAD. Сам шифр не прошёл независимый криптоанализ — см.
//! корневой `docs/DISCLAIMER.md`.
//!
//! ## Известное архитектурное ограничение
//!
//! Весь входной файл читается в память целиком (`fs::read`). Для больших
//! файлов это означает пропорционально большое потребление RAM и
//! потенциальный OOM. Потоковое (chunked) шифрование — открытая задача,
//! не реализовано в этой версии (см. DESIGN_RATIONALE.md).

mod format;

use clap::{Parser, Subcommand};
use format::{build_file, parse_file, FormatError, NONCE_LEN, SALT_LEN};
use rand::{rngs::OsRng, RngCore};
use skhoron_quark_aead::{QuarkAead, QuarkAeadError};
use skhoron_quark_kdf::{SkhoronKdf, SkhoronKdfError};
use std::fmt;
use std::fs;
use std::io::{self, Write};
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

/// Ошибки этого CLI. Раньше ошибки KDF пробрасывались через `.expect()`
/// (паника вместо контролируемого выхода) — исправлено: теперь все пути
/// ошибок проходят через обычный `Result` и завершаются понятным
/// сообщением с корректным кодом выхода, без паники.
#[derive(Debug)]
enum CliError {
    Io(io::Error),
    PasswordRead(io::Error),
    PasswordMismatch,
    Kdf(SkhoronKdfError),
    Aead(QuarkAeadError),
    Format(FormatError),
    OutputExists(PathBuf),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "ошибка ввода-вывода: {e}"),
            CliError::PasswordRead(e) => write!(f, "не удалось прочитать пароль: {e}"),
            CliError::PasswordMismatch => write!(f, "пароли не совпадают"),
            CliError::Kdf(e) => write!(f, "ошибка вывода ключа (Argon2id/HKDF): {e}"),
            CliError::Aead(e) => write!(f, "ошибка шифрования/расшифровки: {e}"),
            CliError::Format(e) => write!(f, "ошибка формата файла: {e}"),
            CliError::OutputExists(p) => {
                write!(f, "файл {p:?} уже существует, используйте --force для перезаписи")
            }
        }
    }
}

/// Читает пароль без эха на терминал. Раньше ошибка чтения (например,
/// stdin не TTY) молча превращалась в пустой пароль через
/// `unwrap_or_default()` — очень плохой паттерн для security-CLI: сбой
/// ввода становился бы неотличим от "пользователь ввёл пустой пароль".
/// Теперь ошибка явно пробрасывается наверх.
fn read_password(prompt: &str) -> Result<String, CliError> {
    print!("{prompt}");
    io::stdout().flush().map_err(CliError::PasswordRead)?;
    rpassword::read_password().map_err(CliError::PasswordRead)
}

/// Раньше использовался `.expect(...)` — паника вместо контролируемой
/// ошибки. Argon2id/HKDF могут реалистично вернуть ошибку (например,
/// некорректные параметры), и security-sensitive CLI не должен падать
/// с паникой на пользовательском вводе.
fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let kdf = SkhoronKdf::default_params();
    let master = kdf.derive_master_secret(password, salt).map_err(CliError::Kdf)?;
    let key_bytes = master
        .derive_subkey(b"skhoron-quark-file:encryption-key-v1", 32)
        .map_err(CliError::Kdf)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

fn print_disclaimer() {
    eprintln!("⚠️  Skhoron-Quark — экспериментальный шифр, не прошёл независимый аудит.");
    eprintln!("    Не используйте для защиты реальных секретов. Продолжаю по вашему запросу.\n");
}

fn check_output_allowed(output: &Path, force: bool) -> Result<(), CliError> {
    if output.exists() && !force {
        return Err(CliError::OutputExists(output.to_path_buf()));
    }
    Ok(())
}

fn write_atomic(output: &Path, data: &[u8]) -> Result<(), CliError> {
    let tmp_path = output.with_extension("tmp");
    {
        let mut tmp_file = fs::File::create(&tmp_path).map_err(CliError::Io)?;
        tmp_file.write_all(data).map_err(CliError::Io)?;
        tmp_file.sync_all().map_err(CliError::Io)?;
    }
    fs::rename(&tmp_path, output).map_err(CliError::Io)?;
    Ok(())
}

fn run_encrypt(input: PathBuf, output: PathBuf, force: bool) -> Result<(), CliError> {
    check_output_allowed(&output, force)?;

    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(fs::read(&input).map_err(CliError::Io)?);

    let mut password = read_password("Пароль для шифрования: ")?;
    let mut confirm = read_password("Повторите пароль: ")?;
    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err(CliError::PasswordMismatch);
    }
    confirm.zeroize();

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(&password, &salt)?;
    password.zeroize();

    let aead = QuarkAead::new(*key);

    let mut header_for_aad = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN);
    header_for_aad.extend_from_slice(format::MAGIC);
    header_for_aad.push(format::VERSION);
    header_for_aad.extend_from_slice(&salt);
    header_for_aad.extend_from_slice(&nonce);

    let ciphertext_and_tag = aead
        .encrypt_with_nonce(&nonce, &plaintext, &header_for_aad)
        .map_err(CliError::Aead)?;

    let file_bytes = build_file(&salt, &nonce, &ciphertext_and_tag);
    write_atomic(&output, &file_bytes)?;

    println!("Зашифровано: {input:?} -> {output:?} ({} байт)", file_bytes.len());
    Ok(())
}

fn run_decrypt(input: PathBuf, output: PathBuf, force: bool) -> Result<(), CliError> {
    check_output_allowed(&output, force)?;

    let file_bytes = fs::read(&input).map_err(CliError::Io)?;
    let parsed = parse_file(&file_bytes).map_err(CliError::Format)?;

    let mut password = read_password("Пароль для расшифровки: ")?;
    let key = derive_key(&password, parsed.salt)?;
    password.zeroize();

    let aead = QuarkAead::new(*key);

    let plaintext = aead
        .decrypt_with_nonce(&parsed.nonce, parsed.ciphertext_and_tag, parsed.header_bytes)
        .map_err(CliError::Aead)?;
    let plaintext = Zeroizing::new(plaintext);

    write_atomic(&output, &plaintext)?;
    println!("Расшифровано: {input:?} -> {output:?} ({} байт)", plaintext.len());
    Ok(())
}

fn main() {
    print_disclaimer();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Encrypt { input, output, force } => run_encrypt(input, output, force),
        Command::Decrypt { input, output, force } => run_decrypt(input, output, force),
    };

    if let Err(e) = result {
        eprintln!("Ошибка: {e}");
        std::process::exit(1);
    }
}