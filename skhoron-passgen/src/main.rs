//! Skhoron-Passgen — CLI: генерация паролей + хеширование + проверка.
//!
//! ⚠️ Хранит только Argon2id-хеши сгенерированных паролей, НЕ сами
//! пароли. Сам сгенерированный пароль показывается один раз в терминале.

mod charset;
mod generator;
mod hasher;
mod store;

use charset::CharsetOptions;
use clap::{Parser, Subcommand, ValueEnum};
use hasher::{HashParams, PasswordHasherWrapper};
use std::io::{self, Write};
use std::path::PathBuf;
use store::PasswordStore;

#[derive(Parser)]
#[command(name = "skhoron-passgen", about = "Генератор паролей с хешированием (Argon2id)")]
struct Cli {
    #[arg(long, default_value = "skhoron-passgen-store.txt")]
    store: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Argon2Profile {
    Mobile,
    Desktop,
}

impl Argon2Profile {
    fn to_hash_params(self) -> HashParams {
        match self {
            Argon2Profile::Mobile => HashParams::mobile(),
            Argon2Profile::Desktop => HashParams::desktop(),
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Сгенерировать пароль и вывести его (без сохранения).
    Generate {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// Сгенерировать пароль, сохранить его Argon2id-хеш под меткой
    /// `label`, и только ПОСЛЕ успешного сохранения показать пароль.
    New {
        label: String,
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        exclude_ambiguous: bool,
        #[arg(long, value_enum, default_value_t = Argon2Profile::Mobile)]
        argon2_profile: Argon2Profile,
    },
    /// Проверить введённый пароль против сохранённого хеша по метке.
    Verify { label: String },
    /// Показать список меток в хранилище.
    List,
    /// Удалить метку из хранилища (запрашивает подтверждение, если не
    /// передан флаг --yes).
    Remove {
        label: String,
        #[arg(long)]
        yes: bool,
    },
}

/// Читает пароль без эха на терминал. В отличие от предыдущей версии,
/// НЕ глотает ошибку чтения молча в пустую строку (`unwrap_or_default()`)
/// — ошибка ввода (например, stdin не является TTY) теперь явно
/// пробрасывается наверх и обрабатывается вызывающим кодом.
fn read_password_hidden(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    rpassword::read_password()
}

fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N] ");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            length,
            count,
            no_symbols,
            exclude_ambiguous,
        } => {
            let opts = CharsetOptions {
                symbols: !no_symbols,
                exclude_ambiguous,
                ..Default::default()
            };
            let alphabet_len = charset::build_charset(opts).len();
            let entropy = charset::entropy_bits(alphabet_len, length);

            match generator::generate_candidates(count, length, opts) {
                Ok(passwords) => {
                    for pw in &passwords {
                        println!("{}", &**pw);
                    }
                    eprintln!("\nТеоретическая энтропия: ~{entropy:.1} бит (алфавит: {alphabet_len} символов)");
                }
                Err(e) => {
                    eprintln!("Ошибка генерации: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::New {
            label,
            length,
            no_symbols,
            exclude_ambiguous,
            argon2_profile,
        } => {
            let opts = CharsetOptions {
                symbols: !no_symbols,
                exclude_ambiguous,
                ..Default::default()
            };

            let password = match generator::generate_password(length, opts) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Ошибка генерации: {e}");
                    std::process::exit(1);
                }
            };

            let hasher = match PasswordHasherWrapper::new(argon2_profile.to_hash_params()) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Ошибка инициализации Argon2id: {e}");
                    std::process::exit(1);
                }
            };

            let phc_hash = match hasher.hash(&password) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Ошибка хеширования: {e}");
                    std::process::exit(1);
                }
            };

            // ВАЖНО: порядок исправлен по ревью — сначала сохраняем хеш,
            // и ТОЛЬКО после подтверждённого успешного сохранения
            // показываем пароль. Раньше пароль печатался ДО попытки
            // сохранения — если сохранение падало (например, диск полон),
            // пользователь мог решить, что пароль сохранён, хотя запись
            // не появилась.
            let mut store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };

            if let Err(e) = store.add(&label, &phc_hash) {
                eprintln!("Ошибка сохранения: {e}");
                eprintln!("Пароль НЕ сохранён и НЕ показан. Попробуйте снова.");
                std::process::exit(1);
            }

            println!("Хеш успешно сохранён под меткой {label:?} в {:?}", cli.store);
            println!("\nВАЖНО: сохраните пароль сейчас, он больше не будет показан:");
            println!("{}", &*password);
        }

        Command::Verify { label } => {
            let store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };

            let stored_hash = match store.get(&label) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            let entered = match read_password_hidden("Введите пароль для проверки: ") {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("\nОшибка чтения пароля: {e}");
                    std::process::exit(1);
                }
            };

            let hasher = PasswordHasherWrapper::default_params();
            match hasher.verify(&entered, stored_hash) {
                Ok(true) => println!("\n✅ Пароль верный"),
                Ok(false) => {
                    println!("\n❌ Пароль неверный");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Ошибка проверки: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::List => {
            let store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };
            for label in store.list_labels() {
                println!("{label}");
            }
        }

        Command::Remove { label, yes } => {
            let mut store = match PasswordStore::load_or_create(&cli.store) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка открытия хранилища: {e}");
                    std::process::exit(1);
                }
            };

            if !yes && !confirm(&format!("Удалить метку {label:?}?")) {
                println!("Отменено.");
                return;
            }

            match store.remove(&label) {
                Ok(()) => println!("Метка {label:?} удалена"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
    }
}