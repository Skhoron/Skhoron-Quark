impl QuarkKey {
    /// Шифрует один блок из произвольного byte slice.
    ///
    /// Требуется ровно 32 байта.
    pub fn try_encrypt_block(
        &self,
        plaintext: &[u8],
    ) -> Result<[u8; BLOCK_SIZE_BYTES], QuarkCoreError> {
        if plaintext.len() != BLOCK_SIZE_BYTES {
            return Err(QuarkCoreError::InvalidBlockLength(
                plaintext.len(),
            ));
        }

        let mut block = [0u8; BLOCK_SIZE_BYTES];

        block.copy_from_slice(plaintext);

        let ciphertext = self.encrypt_block(&block);

        block.zeroize();

        Ok(ciphertext)
    }

    /// Расшифровывает один блок из произвольного byte slice.
    ///
    /// Требуется ровно 32 байта.
    pub fn try_decrypt_block(
        &self,
        ciphertext: &[u8],
    ) -> Result<[u8; BLOCK_SIZE_BYTES], QuarkCoreError> {
        if ciphertext.len() != BLOCK_SIZE_BYTES {
            return Err(QuarkCoreError::InvalidBlockLength(
                ciphertext.len(),
            ));
        }

        let mut block = [0u8; BLOCK_SIZE_BYTES];

        block.copy_from_slice(ciphertext);

        let plaintext = self.decrypt_block(&block);

        block.zeroize();

        Ok(plaintext)
    }
}