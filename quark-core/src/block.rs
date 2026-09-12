impl QuarkKey {
    /// Создаёт ключ из произвольного байтового среза.
    ///
    /// Требуется ровно 32 байта.
    pub fn try_new(key_bytes: &[u8]) -> Result<Self, QuarkCoreError> {
        if key_bytes.len() != BLOCK_SIZE_BYTES {
            return Err(QuarkCoreError::InvalidKeyLength(key_bytes.len()));
        }

        let mut fixed_key = [0u8; BLOCK_SIZE_BYTES];

        fixed_key.copy_from_slice(key_bytes);

        let key = Self::new(fixed_key);

        fixed_key.zeroize();

        Ok(key)
    }
}