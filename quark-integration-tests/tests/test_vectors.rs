//! Known-answer tests (KAT) for Skhoron-Quark.
//!
//! These vectors are deterministic self-consistency vectors for the
//! current Skhoron-Quark specification.
//!
//! They are not external standardized vectors. Their purpose is to detect
//! accidental changes in the algorithm implementation, including:
//! - round function changes;
//! - key schedule changes;
//! - state layout changes;
//! - endian/layout regressions;
//! - rotation/permutation changes.
//!
//! If the cipher specification intentionally changes, the KAT vector must
//! be regenerated as part of that specification change.

use skhoron_quark_core::QuarkKey;

#[test]
fn kat_zero_block_zero_plaintext_fixed_key() {
    let key = QuarkKey::new([
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
    ]);

    let plaintext = [0u8; 32];

    let expected_ciphertext = [
        0xA6, 0x5D, 0x69, 0xF2,
        0xD1, 0x9A, 0x00, 0xF8,
        0x6A, 0xAC, 0xDD, 0x52,
        0x6C, 0xEB, 0xE1, 0xD9,
        0x91, 0x6F, 0xC4, 0xB7,
        0x59, 0x37, 0x73, 0xBF,
        0x4A, 0x97, 0xA6, 0xA4,
        0xFB, 0x94, 0xA3, 0x22,
    ];

    let ciphertext = key.encrypt_block(&plaintext);

    assert_eq!(
        ciphertext,
        expected_ciphertext,
        "Skhoron-Quark KAT mismatch: implementation changed"
    );
}

#[test]
fn kat_zero_block_roundtrip() {
    let key = QuarkKey::new([
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
    ]);

    let plaintext = [0u8; 32];

    let ciphertext = key.encrypt_block(&plaintext);
    let decrypted = key.decrypt_block(&ciphertext);

    assert_eq!(
        decrypted,
        plaintext,
        "decrypt(encrypt(plaintext)) must recover plaintext"
    );
}