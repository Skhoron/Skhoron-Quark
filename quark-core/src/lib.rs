//! # Skhoron-Quark — core
//!
//! ⚠️ **ЭКСПЕРИМЕНТАЛЬНЫЙ КРИПТОГРАФИЧЕСКИЙ ПРИМИТИВ. НЕ ДЛЯ ПРОДАКШЕНА.**
//!
//! Этот шифр — учебный/исследовательский проект. Он НЕ прошёл независимый
//! криптоанализ, НЕ проверялся профессиональным сообществом и НЕ должен
//! использоваться для защиты реальных данных, денег или переписки.
//!
//! Для реальной защиты данных используйте проверенные десятилетиями
//! стандарты: AES-256-GCM, XChaCha20-Poly1305 (crate `chacha20poly1305`
//! из экосистемы RustCrypto).
//!
//! Подробности статуса: см. `docs/DISCLAIMER.md` в репозитории.
//!
//! ## Что это
//!
//! ARX-конструкция (Addition-Rotation-XOR) без S-box, 256-битный блок,
//! 256-битный ключ. Структура раунда: Sum-layer → Cross-XOR-layer →
//! Rotation-layer. Обоснование конструкции — `docs/DESIGN_RATIONALE.md`.
//!
//! ## Пример
//!
//! ```
//! use skhoron_quark_core::QuarkKey;
//!
//! let key = QuarkKey::new([0x42; 32]);
//! let plaintext = [0u8; 32];
//! let ciphertext = key.encrypt_block(&plaintext);
//! let decrypted = key.decrypt_block(&ciphertext);
//! assert_eq!(decrypted, plaintext);
//! ```

pub mod block;
pub mod constants;
pub mod key_schedule;
pub mod round;

pub use block::{QuarkKey, BLOCK_SIZE_BYTES};