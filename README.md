Skhoron-Quark

«⚠️ Experimental cryptographic primitive. NOT for production use.

See ""docs/DISCLAIMER.md"" (docs/DISCLAIMER.md).

For real data protection, use AES-256-GCM or XChaCha20-Poly1305 (RustCrypto: "aes-gcm", "chacha20poly1305").»

An experimental ARX-based (Addition-Rotation-XOR) block cipher with a 256-bit block and a 256-bit key, without S-boxes.

This is a research and educational project within the "Skhoron" (https://github.com/Skhoron) ecosystem, published openly from day one in accordance with Kerckhoffs's principle: the cipher's design is not concealed until it is considered "ready."

The rationale behind every design decision is documented in ""docs/DESIGN_RATIONALE.md"" (docs/DESIGN_RATIONALE.md).

Repository Structure

Crate| Purpose
"quark-core"| The block cipher itself: round function, key schedule, and block encryption/decryption.
"quark-aead"| Authenticated encryption built on top of the core: CTR mode, BLAKE3-based MAC, and nonce handling.
"quark-kdf"| Argon2id + HKDF: deriving keys from user passwords with domain separation.
"quark-keygen"| Generates a random 256-bit key directly using the operating system's cryptographically secure random number generator (OS CSPRNG).
"quark-integration-tests"| End-to-end tests for the complete pipeline: password → key → AEAD.
"quark-file"| CLI for actual file encryption/decryption using Quark: password → Argon2id/HKDF → key → AEAD → file on disk.
"analysis/"| Python scripts for cryptanalysis, including branch number analysis, avalanche testing, and a starting point for SAT/MILP analysis. Not part of the cipher itself.
"docs/"| Design rationale and disclaimer.

Quick Start

Encrypting Files via the CLI

Encrypt a file:

cargo run --release -p skhoron-quark-file -- encrypt secret.txt secret.txt.skhq

Decrypt a file:

cargo run --release -p skhoron-quark-file -- decrypt secret.txt.skhq secret_restored.txt

To explicitly allow overwriting an existing output file:

cargo run --release -p skhoron-quark-file -- encrypt secret.txt secret.txt.skhq --force

The ".skhq" format consists of: magic bytes → version → Argon2id salt → nonce → ciphertext + MAC.

See "quark-file/src/format.rs" for details.

Using It as a Library

use skhoron_quark_aead::QuarkAead;
use skhoron_quark_keygen::generate_key;

// 1. Generate a random key (or derive one from a password using quark-kdf)
let key_bytes = generate_key();

// 2. AEAD encryption — a safer high-level API.
// The nonce is generated automatically inside encrypt(),
// preventing callers from accidentally reusing a nonce.
let aead = QuarkAead::new(*key_bytes);
let (nonce, ciphertext) = aead.encrypt(b"hello, quark", b"");
let plaintext = aead.decrypt(&nonce, &ciphertext, b"").unwrap();

assert_eq!(plaintext, b"hello, quark");

The low-level API ("encrypt_with_nonce" / "decrypt_with_nonce") is available when the nonce needs to be stored or transmitted separately. This is what "quark-file" does, since the nonce is already stored in the ".skhq" file header.

Build and Test

Build the entire workspace:

cargo build --workspace

Run all tests:

cargo test --workspace

Run Clippy and treat all warnings as errors:

cargo clippy --workspace -- -D warnings

«The code in this repository has not been compiled in the environment where it was written because network access was unavailable for downloading crates. Build the project and run the tests locally before using it.

One test ("test_vectors.rs") contains a placeholder value that must be replaced with the actual value after the first successful run. Instructions are provided in the file itself.»

Design Status

- Avalanche effect in the round function. Experimentally tested. The original three-layer design had a structural flaw: words were not fully mixed. This was fixed by adding a permutation layer. See "docs/DESIGN_RATIONALE.md", Section 2.1.

- Key schedule. A similar flaw was found: a difference in one key word did not propagate beyond that word until round 24. This was fixed by reusing "forward_round" instead of updating the words independently. See Section 5.

- AEAD API. A bug was found: "encrypt()" and "decrypt()" were asymmetric because of an embedded nonce, which meant decryption in "quark-file" was guaranteed to fail. This was fixed by separating the API into "encrypt" / "decrypt" (high-level) and "encrypt_with_nonce" / "decrypt_with_nonce" (low-level). See Section 8.

- Rotation constants and number of rounds. The parameters, including the 24-round count, are still preliminary and have not undergone formal differential or linear cryptanalysis.

- File handling. "quark-file" reads the entire file into memory. Streaming encryption has not been implemented yet. See Section 9 for open tasks.

The full list of outstanding tasks is provided at the end of "docs/DESIGN_RATIONALE.md".

License

Apache License 2.0. See ""LICENSE"" (LICENSE).

Contributing

See ""CONTRIBUTING.md"" (CONTRIBUTING.md) for contribution guidelines.