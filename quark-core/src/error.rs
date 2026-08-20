//! Типы ошибок quark-core.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuarkCoreError {
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("invalid block length: expected 32 bytes, got {0}")]
    InvalidBlockLength(usize),
}