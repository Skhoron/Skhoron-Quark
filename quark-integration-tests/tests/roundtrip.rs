//! Full cross-crate integration tests for Skhoron-Quark.
//!
//! These tests intentionally use only public APIs, simulating how an
//! external Rust application would consume the Skhoron-Quark crates.

use skhoron_quark_aead::{generate_nonce, QuarkAead};
use skhoron_quark_core::QuarkKey;
use skhoron_quark_kdf::SkhoronKdf;
use skhoron_quark_keygen::generate_key;

#[test]
fn full_password_to_aead_pipeline() {
    let kdf = SkhoronKdf::default_params();

    let salt = b"unique-per-user-salt-16bytes!!!";

    let master = kdf
        .derive_master_secret(
            "correct horse battery staple",
            salt,
        )
        .expect("KDF must derive master secret");

    let enc_key: [u8; 32] = master
        .derive_subkey(
            b"skhoron-quark:example-message-key",
            32,
        )
        .expect("HKDF must derive encryption key")
        .as_slice()
        .try_into()
        .expect("derived key must be exactly 32 bytes");

    let aead = QuarkAead::new(enc_key);

    let nonce = generate_nonce();

    let plaintext =
        b"integration test across the full Skhoron-Quark pipeline";

    let associated_data =
        b"skhoron-quark-integration-test";

    let ciphertext = aead
        .encrypt_with_nonce(
            &nonce,
            plaintext,
            associated_data,
        )
        .expect("encryption must succeed");

    assert_ne!(
        ciphertext,
        plaintext,
        "ciphertext must not equal plaintext"
    );

    let decrypted = aead
        .decrypt_with_nonce(
            &nonce,
            &ciphertext,
            associated_data,
        )
        .expect("decryption must succeed");

    assert_eq!(
        decrypted,
        plaintext,
        "decrypt(encrypt(plaintext)) must recover plaintext"
    );
}

#[test]
fn aead_rejects_modified_ciphertext() {
    let key = [0x42u8; 32];
    let aead = QuarkAead::new(key);

    let nonce = generate_nonce();

    let plaintext = b"authenticated message";
    let aad = b"associated data";

    let mut ciphertext = aead
        .encrypt_with_nonce(&nonce, plaintext, aad)
        .expect("encryption must succeed");

    assert!(
        !ciphertext.is_empty(),
        "test ciphertext must contain authentication material"
    );

    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(
        aead.decrypt_with_nonce(&nonce, &ciphertext, aad).is_err(),
        "modified ciphertext must fail authentication"
    );
}

#[test]
fn aead_rejects_modified_associated_data() {
    let key = [0x42u8; 32];
    let aead = QuarkAead::new(key);

    let nonce = generate_nonce();

    let plaintext = b"authenticated message";
    let aad = b"original associated data";

    let ciphertext = aead
        .encrypt_with_nonce(&nonce, plaintext, aad)
        .expect("encryption must succeed");

    assert!(
        aead.decrypt_with_nonce(
            &nonce,
            &ciphertext,
            b"modified associated data"
        )
        .is_err(),
        "modified AAD must fail authentication"
    );
}

#[test]
fn keygen_produces_usable_block_cipher_key() {
    let key_bytes = generate_key();

    assert_eq!(
        key_bytes.len(),
        32,
        "generated key must contain 32 bytes"
    );

    let key = QuarkKey::new(*key_bytes);

    let plaintext = [0xAAu8; 32];

    let ciphertext = key.encrypt_block(&plaintext);

    assert_ne!(
        ciphertext,
        plaintext,
        "ciphertext must differ from plaintext"
    );

    let decrypted = key.decrypt_block(&ciphertext);

    assert_eq!(
        decrypted,
        plaintext,
        "block cipher roundtrip must succeed"
    );
}

#[test]
fn different_keys_produce_different_ciphertext() {
    let plaintext = [0x55u8; 32];

    let key_a = QuarkKey::new([0x01u8; 32]);
    let key_b = QuarkKey::new([0x02u8; 32]);

    let ciphertext_a = key_a.encrypt_block(&plaintext);
    let ciphertext_b = key_b.encrypt_block(&plaintext);

    assert_ne!(
        ciphertext_a,
        ciphertext_b,
        "different keys must produce different ciphertext"
    );
}