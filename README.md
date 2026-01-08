# Saorsa Post-Quantum Cryptography Library

[![Crates.io](https://img.shields.io/crates/v/saorsa-pqc.svg)](https://crates.io/crates/saorsa-pqc)
[![Documentation](https://docs.rs/saorsa-pqc/badge.svg)](https://docs.rs/saorsa-pqc)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/dirvine/saorsa-pqc)
[![Build Status](https://github.com/dirvine/saorsa-pqc/workflows/CI/badge.svg)](https://github.com/dirvine/saorsa-pqc/actions)

A comprehensive, production-ready Post-Quantum Cryptography library providing a complete quantum-secure cryptographic suite. Implements NIST FIPS 203, 204, and 205 standardized algorithms for asymmetric cryptography, plus comprehensive cryptographic primitives including BLAKE3, SHA3, HMAC, HKDF, AES-256-GCM, and ChaCha20-Poly1305. This library provides high-performance, thoroughly tested implementations with a clean, safe API, all validated against official NIST ACVP, RFC, and specification test vectors.

## 🎯 Features

- **Complete Quantum-Secure Suite**: Both asymmetric (PQC) and symmetric encryption with comprehensive cryptographic primitives
- **FIPS 140-3 Compliant RNG**: ChaCha20-based DRBG with continuous health monitoring per NIST SP 800-90A/B
- **FIPS-Certified Implementations**: Uses NIST FIPS-certified crates for ML-KEM, ML-DSA, and SLH-DSA
- **Extensive Cryptographic Library**: BLAKE3, SHA3, HMAC, HKDF, AES-256-GCM, ChaCha20-Poly1305, and HPKE
- **Official Test Vector Validation**: All algorithms validated against NIST ACVP, RFC, and specification test vectors
- **Comprehensive API**: Simple, user-friendly interfaces with FIPS-compliant RNG management
- **High Performance**: Optimized implementations with SIMD support where available
- **Memory Safety**: Automatic zeroization of sensitive data
- **Type Safety**: Strongly typed wrappers prevent misuse
- **No Unsafe Code**: Pure Rust implementations in the API layer
- **Deterministic Testing**: Support for reproducible key generation from seeds

## 📦 Installation

```toml
[dependencies]
saorsa-pqc = "0.4"
```

## 🔐 Supported Algorithms

### 🔒 Cryptographic Primitives (All Quantum-Resistant)

#### Hash Functions
- **BLAKE3**: Modern cryptographic hash with tree hashing
  - ✅ **High Performance**: Faster than SHA2/SHA3 with parallelization
  - ✅ **256-bit Output**: Configurable output length (XOF capability)
  - ✅ **Test Vectors**: Validated against official BLAKE3 specification vectors
  - ✅ **Use Cases**: General hashing, key derivation, checksums

- **SHA3-256/SHA3-512**: NIST FIPS 202 Keccak-based hash functions
  - ✅ **NIST Standard**: FIPS 202 compliant implementation
  - ✅ **Quantum Resistance**: Based on different mathematical foundation than SHA2
  - ✅ **Test Vectors**: Validated against NIST FIPS 202 official test vectors
  - ✅ **Use Cases**: Digital signatures, certificates, blockchain applications

#### Key Derivation Functions (KDF)
- **HKDF-SHA3-256/HKDF-SHA3-512**: Extract-and-expand key derivation
  - ✅ **RFC 5869 Based**: Adapted for SHA3 hash functions
  - ✅ **Secure Key Derivation**: Extract entropy then expand to desired length
  - ✅ **Test Vectors**: Validated against RFC 5869 methodology
  - ✅ **Use Cases**: Deriving encryption keys from shared secrets

#### Message Authentication Codes (MAC)
- **HMAC-SHA3-256/HMAC-SHA3-512**: Hash-based message authentication
  - ✅ **Constant-Time Verification**: Resistant to timing attacks
  - ✅ **NIST CAVS Tested**: Validated against NIST test methodology
  - ✅ **Flexible Key Sizes**: Accepts arbitrary key lengths
  - ✅ **Use Cases**: Message integrity, authentication tokens

#### Authenticated Encryption (AEAD)
- **AES-256-GCM**: Hardware-accelerated authenticated encryption
  - ✅ **Hardware Support**: AES-NI acceleration on modern CPUs
  - ✅ **256-bit Security**: Quantum-resistant key size
  - ✅ **NIST CAVP Tested**: Validated against NIST SP 800-38D test vectors
  - ✅ **Use Cases**: High-speed data encryption, VPN tunnels

- **ChaCha20-Poly1305**: Software-optimized authenticated encryption
  - ✅ **Constant-Time**: Resistant to side-channel attacks
  - ✅ **256-bit Security**: Full 256-bit key strength
  - ✅ **IETF Standard**: RFC 8439 compliant
  - ✅ **Test Vectors**: Validated against RFC 8439 official test vectors
  - ✅ **Use Cases**: Mobile devices, embedded systems, general encryption

#### Hybrid Public Key Encryption (HPKE)
- **HPKE with ML-KEM**: RFC 9180 hybrid encryption bound to post-quantum KEMs
  - ✅ **Post-Quantum**: Combines ML-KEM with symmetric primitives
  - ✅ **Multiple Modes**: Base mode and PSK (pre-shared key) mode
  - ✅ **Flexible Configuration**: Choose KEM (ML-KEM variant), KDF, and AEAD
  - ✅ **Test Vectors**: Custom test vectors for ML-KEM combinations
  - ✅ **Use Cases**: End-to-end encryption, secure messaging, hybrid cryptosystems

### ML-KEM (FIPS 203) - Key Encapsulation
- **ML-KEM-512**: NIST Level 1 (128-bit security)
- **ML-KEM-768**: NIST Level 3 (192-bit security)
- **ML-KEM-1024**: NIST Level 5 (256-bit security)

### ML-DSA (FIPS 204) - Digital Signatures
- **ML-DSA-44**: NIST Level 2 (~128-bit security)
- **ML-DSA-65**: NIST Level 3 (~192-bit security)
- **ML-DSA-87**: NIST Level 5 (~256-bit security)

### SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures
12 variants covering all combinations of:
- Hash functions: SHA2, SHAKE
- Security levels: 128, 192, 256 bits
- Trade-offs: Small signatures (s) vs Fast signing (f)

## 💻 Quick Start

### NEW: Trait-Based API (v0.3.11+)

The library now provides a trait-based abstraction layer for PQC algorithms, enabling easier integration and algorithm agility:

```rust
use saorsa_pqc::pqc::{Kem, Sig, MlKem768Trait, MlDsa65Trait, ConstantTimeCompare};

// Key Encapsulation with trait API
let (kem_pk, kem_sk) = MlKem768Trait::keypair();
let (shared_secret, ciphertext) = MlKem768Trait::encap(&kem_pk);
let recovered = MlKem768Trait::decap(&kem_sk, &ciphertext)?;
assert!(shared_secret.ct_eq(&recovered)); // Constant-time comparison

// Digital Signatures with trait API
let (sig_pk, sig_sk) = MlDsa65Trait::keypair();
let message = b"Quantum-resistant message";
let signature = MlDsa65Trait::sign(&sig_sk, message);
assert!(MlDsa65Trait::verify(&sig_pk, message, &signature));

// BLAKE3 helpers for secure key derivation
use saorsa_pqc::pqc::blake3_helpers;
let derived_key = blake3_helpers::derive_key("app-context", shared_secret.as_ref());
```

**Key Features of Trait API:**
- **Zero-copy buffers**: Efficient memory usage without unnecessary allocations
- **Automatic zeroization**: Secret keys are wiped from memory when dropped
- **Constant-time operations**: Protection against timing attacks
- **Generic programming**: Write code that works with any KEM or signature algorithm

### Quantum-Secure Symmetric Encryption (ChaCha20-Poly1305)

```rust
use saorsa_pqc::api::ChaCha20Poly1305;
use saorsa_pqc::api::symmetric::{generate_key, generate_nonce};

// Generate a random 256-bit key (quantum-secure)
let key = generate_key();
let cipher = ChaCha20Poly1305::new(&key);

// Encrypt data with authenticated encryption
let nonce = generate_nonce(); // 96-bit nonce
let plaintext = b"Secret quantum-secure message";
let aad = b"Additional authenticated data";

// Encrypt with associated data (AEAD)
let ciphertext = cipher.encrypt_with_aad(&nonce, plaintext, aad)?;

// Decrypt and verify authenticity
let decrypted = cipher.decrypt_with_aad(&nonce, &ciphertext, aad)?;

assert_eq!(&decrypted[..], plaintext);

// Simple encryption without AAD
let ciphertext2 = cipher.encrypt(&nonce, plaintext)?;
let decrypted2 = cipher.decrypt(&nonce, &ciphertext2)?;
assert_eq!(&decrypted2[..], plaintext);
```

### Key Encapsulation (ML-KEM)

```rust
use saorsa_pqc::api::{ml_kem_768, MlKemPublicKey, MlKemSecretKey};

// Generate keypair (RNG handled internally)
let kem = ml_kem_768();
let (public_key, secret_key) = kem.generate_keypair()?;

// Encapsulate - creates shared secret and ciphertext
let (shared_secret, ciphertext) = kem.encapsulate(&public_key)?;

// Decapsulate - recovers shared secret from ciphertext
let recovered_secret = kem.decapsulate(&secret_key, &ciphertext)?;

assert_eq!(shared_secret.to_bytes(), recovered_secret.to_bytes());
```

### Digital Signatures (ML-DSA)

```rust
use saorsa_pqc::api::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

// Generate keypair
let dsa = ml_dsa_65();
let (public_key, secret_key) = dsa.generate_keypair()?;

// Sign message
let message = b"Authenticate this message";
let signature = dsa.sign(&secret_key, message)?;

// Verify signature
let is_valid = dsa.verify(&public_key, message, &signature)?;
assert!(is_valid);
```

### Stateless Signatures (SLH-DSA)

```rust
use saorsa_pqc::api::{slh_dsa_sha2_128s, SlhDsaPublicKey, SlhDsaSecretKey};

// Generate keypair (note: SLH-DSA keygen is slow)
let slh = slh_dsa_sha2_128s();
let (public_key, secret_key) = slh.generate_keypair()?;

// Sign and verify
let message = b"Quantum-resistant message";
let signature = slh.sign(&secret_key, message)?;
let is_valid = slh.verify(&public_key, message, &signature)?;
assert!(is_valid);
```

## 🧪 Testing & Validation

This library has been extensively tested against official test vectors from multiple authoritative sources:

### Comprehensive Test Vector Validation

#### Post-Quantum Algorithms (NIST ACVP)
- **Official NIST ACVP Vectors**: [github.com/usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files)
  - ✅ **ML-KEM**: [Keygen](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203), [Encapsulation/Decapsulation](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)
  - ✅ **ML-DSA**: [Keygen](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204), [Signature Generation/Verification](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204)
  - ✅ **SLH-DSA**: [Comprehensive test vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205) for all 12 variants

#### Cryptographic Primitives (Official Standards)
- ✅ **BLAKE3**: Official specification test vectors from [BLAKE3 team](https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json)
- ✅ **SHA3-256/512**: NIST FIPS 202 test vectors for empty input, "abc", and multi-million character tests
- ✅ **AES-256-GCM**: NIST CAVP test vectors from SP 800-38D with various key, IV, and AAD combinations
- ✅ **HKDF-SHA3**: Test vectors adapted from RFC 5869 methodology for SHA3 variants
- ✅ **HMAC-SHA3**: Test vectors derived from NIST CAVS testing methodology
- ✅ **ChaCha20-Poly1305**: RFC 8439 official test vectors
- ✅ **HPKE**: RFC 9180 methodology adapted for ML-KEM combinations

#### Additional Test Sources
- **C2SP/CCTV Test Vectors**: [github.com/C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/ML-KEM)
  - Intermediate values for debugging
  - Invalid input testing (modulus vectors)
  - Edge case testing (unlucky NTT sampling)

### Running Tests

```bash
# Run all tests
cargo test --all-features

# Run specific algorithm tests
cargo test --test nist_official_vectors
cargo test --test extended_crypto_vectors

# Run with release optimizations (faster)
cargo test --release
```

### Test Coverage

#### Post-Quantum Algorithm Coverage
- ✅ Key generation deterministic tests
- ✅ Encapsulation/Decapsulation correctness
- ✅ Signature generation and verification
- ✅ Wrong message/ciphertext rejection
- ✅ Serialization round-trips
- ✅ Context handling (ML-DSA)
- ✅ Parameter validation
- ✅ Cross-implementation compatibility

#### Cryptographic Primitive Coverage
- ✅ **Hash Functions**: BLAKE3 (empty, single byte, multi-part, million character), SHA3-256/512 (NIST FIPS 202)
- ✅ **Key Derivation**: HKDF-SHA3-256/512 deterministic output, salt handling, different context values
- ✅ **Message Authentication**: HMAC-SHA3-256/512 with various key sizes, constant-time verification
- ✅ **AEAD Encryption**: AES-256-GCM and ChaCha20-Poly1305 with AAD, authentication failure detection
- ✅ **HPKE**: All ML-KEM variants with different KDF/AEAD combinations, wrong key rejection
- ✅ **Security Properties**: Memory zeroization, constant-time operations, authentication tag verification
- ✅ **Error Handling**: Invalid input sizes, wrong authentication tags, corrupted data

## 📊 Performance Benchmarks

Run comprehensive benchmarks:

```bash
cargo bench --bench comprehensive_benchmarks
```

### Benchmark Results (M1 Pro)

| Algorithm | Operation | Time | Throughput |
|-----------|-----------|------|------------|
| ML-KEM-768 | KeyGen | ~50 μs | - |
| ML-KEM-768 | Encapsulate | ~55 μs | - |
| ML-KEM-768 | Decapsulate | ~65 μs | - |
| ML-DSA-65 | KeyGen | ~120 μs | - |
| ML-DSA-65 | Sign | ~350 μs | - |
| ML-DSA-65 | Verify | ~130 μs | - |
| SLH-DSA-SHA2-128f | KeyGen | ~3 ms | - |
| SLH-DSA-SHA2-128f | Sign | ~90 ms | - |
| SLH-DSA-SHA2-128f | Verify | ~4 ms | - |
| ChaCha20-Poly1305 | Encrypt (1KB) | ~0.8 μs | 1.25 GB/s |
| ChaCha20-Poly1305 | Encrypt (64KB) | ~12 μs | 5.3 GB/s |
| ChaCha20-Poly1305 | Decrypt (64KB) | ~12 μs | 5.3 GB/s |
| AES-256-GCM | Encrypt (1KB) | ~0.6 μs | 1.67 GB/s |
| AES-256-GCM | Encrypt (64KB) | ~8 μs | 8.0 GB/s |
| BLAKE3 | Hash (1KB) | ~0.4 μs | 2.5 GB/s |
| SHA3-256 | Hash (1KB) | ~1.2 μs | 833 MB/s |
| HMAC-SHA3-256 | MAC (1KB) | ~1.3 μs | 769 MB/s |

*Note: Performance varies by hardware. AES-GCM benefits from AES-NI acceleration. ChaCha20-Poly1305 and BLAKE3 benefit from SIMD acceleration (AVX2/NEON).*

## 🔒 Security Considerations

### Quantum Security
- **Symmetric Algorithms**: All symmetric algorithms (AES-256-GCM, ChaCha20-Poly1305) provide quantum resistance with 256-bit keys, offering 128-bit quantum security against Grover's algorithm
- **Hash Functions**: BLAKE3 and SHA3 maintain security against quantum attacks as they're based on different mathematical foundations
- **Post-Quantum Asymmetric**: ML-KEM, ML-DSA, and SLH-DSA are specifically designed to resist both classical and quantum attacks
- **Complete Protection**: Use ML-KEM for key exchange, then derive symmetric keys for AES-256-GCM or ChaCha20-Poly1305 encryption
- **Algorithm Selection Guide**:
  - **Performance Priority**: BLAKE3 (hashing), AES-256-GCM (encryption if AES-NI available)
  - **Security Priority**: SHA3 (standardized), ChaCha20-Poly1305 (constant-time)
  - **Compatibility**: SHA3 and AES-256-GCM (NIST standards)
  - **Embedded/Mobile**: BLAKE3 and ChaCha20-Poly1305 (software-optimized)

### Implementation Security
1. **Memory Safety**: All sensitive data is automatically zeroized on drop
2. **Constant Time**: Critical operations verified constant-time via DudeCT statistical analysis
3. **FIPS 140-3 RNG**: ChaCha20-based DRBG with continuous health monitoring (SP 800-90A/B compliant)
4. **No Key Reuse**: Fresh randomness for each operation requiring it
5. **Input Validation**: All inputs validated before cryptographic operations
6. **AEAD Protection**: Both AES-256-GCM and ChaCha20-Poly1305 provide confidentiality and authenticity
7. **Algorithm Diversity**: Multiple implementations allow for algorithm agility and risk mitigation
8. **Test Vector Compliance**: All implementations validated against official standards
9. **Formal CT Verification**: DudeCT benchmarks in CI ensure timing attack resistance

### Side-Channel Protection (v0.4.0+)

The library implements comprehensive side-channel protection with **formal verification**:

| Protection | Implementation | Verification |
|------------|----------------|--------------|
| Constant-time comparison | `ct_eq()`, `ct_array_eq()` | DudeCT verified (`max_t < 5`) |
| Constant-time selection | `ct_select()`, `ct_assign()` | DudeCT verified |
| Constant-time copy | `ct_copy_bytes()` | DudeCT verified |
| AAD hash verification | `ct_eq()` in AEAD | Prevents timing oracle |
| Memory clearing | `zeroize` crate | Compiler-resistant zeroing |

**DudeCT Integration**: Every PR is automatically tested for timing leaks:
- Statistical analysis compares timing distributions between input classes
- `|max_t| > 5` indicates non-constant-time behavior (CI fails)
- Extended weekly analysis runs 5-minute tests per primitive

```bash
# Run constant-time verification locally
cargo bench --bench ct_verification
```

### FIPS 140-3 Compliance

The library implements a FIPS 140-3 compliant random number generator:

- **DRBG Mechanism**: ChaCha20-based deterministic random bit generator (approved for FIPS 140-3)
- **Continuous Health Monitoring**: Implements Repetition Count Test (RCT) and Adaptive Proportion Test (APT) per NIST SP 800-90B
- **Entropy Source Validation**: Startup health tests and continuous monitoring of OS entropy
- **Automatic Reseeding**: Reseeds after 1MB of output to ensure prediction resistance and backtracking resistance
- **Security Strengths**: Supports 128-bit, 192-bit, and 256-bit security levels
- **Compliance**: Meets requirements of NIST SP 800-90A (DRBG) and SP 800-90B (Entropy Sources)

```rust
use saorsa_pqc::pqc::{FipsRng, SecurityStrength};

// Create FIPS-compliant RNG for 256-bit security
let mut rng = FipsRng::new(SecurityStrength::Bits256)?;

// Generate cryptographic random bytes
let mut key_material = [0u8; 32];
rng.fill_bytes(&mut key_material);

// Manual reseed for prediction resistance
rng.reseed()?;
```

**Testing**: 29 comprehensive tests validate FIPS compliance including:
- Known Answer Tests (KAT)
- Statistical distribution tests (chi-square)
- Continuous health monitoring
- Reseed mechanisms
- Non-repeatability validation

## 📚 API Documentation

Full API documentation is available at [docs.rs/saorsa-pqc](https://docs.rs/saorsa-pqc)

### Key Types
- `MlKemPublicKey`, `MlKemSecretKey`, `MlKemCiphertext`, `MlKemSharedSecret`
- `MlDsaPublicKey`, `MlDsaSecretKey`, `MlDsaSignature`
- `SlhDsaPublicKey`, `SlhDsaSecretKey`, `SlhDsaSignature`

### Convenience Functions
- `ml_kem_512()`, `ml_kem_768()`, `ml_kem_1024()`
- `ml_dsa_44()`, `ml_dsa_65()`, `ml_dsa_87()`
- `slh_dsa_sha2_128s()`, `slh_dsa_sha2_128f()`, etc.

## 🛠️ Advanced Usage

### Algorithm Selection Guide

Choose the right cryptographic primitives for your use case:

#### Hash Functions
```rust
use saorsa_pqc::api::hash::{Blake3Hasher, Sha3_256Hasher};
use saorsa_pqc::api::traits::Hash;

// High performance: BLAKE3
let mut hasher = Blake3Hasher::new();
hasher.update(b"data to hash");
let hash = hasher.finalize();

// NIST standard: SHA3-256
let mut hasher = Sha3_256Hasher::new();
hasher.update(b"data to hash");
let hash = hasher.finalize();
```

#### AEAD Encryption
```rust
use saorsa_pqc::api::aead::{Aes256GcmAead, AeadCipher, GcmNonce};
use saorsa_pqc::api::traits::Aead;

// Hardware accelerated: AES-256-GCM
let key = [0u8; 32]; // Use proper key generation
let aead = Aes256GcmAead::new(&key)?;
let nonce = GcmNonce::generate();
let ciphertext = aead.encrypt(&nonce, b"plaintext", b"aad")?;

// Software optimized: ChaCha20-Poly1305 (via enum)
let ciphertext = AeadCipher::ChaCha20Poly1305
    .encrypt(&key, nonce.as_ref(), b"plaintext", b"aad")?;
```

#### Key Derivation
```rust
use saorsa_pqc::api::kdf::HkdfSha3_256;
use saorsa_pqc::api::traits::Kdf;

// Derive encryption key from shared secret
let shared_secret = b"shared secret from ML-KEM";
let info = b"application context";
let mut derived_key = [0u8; 32];
HkdfSha3_256::derive(shared_secret, None, info, &mut derived_key)?;
```

#### HPKE (Hybrid Encryption)
```rust
use saorsa_pqc::api::hpke::{HpkeConfig, seal, open};
use saorsa_pqc::api::{MlKem, MlKemVariant, kdf::KdfAlgorithm, aead::AeadCipher};

// Configure HPKE with ML-KEM + AES-GCM
let config = HpkeConfig {
    kem: MlKemVariant::MlKem768,
    kdf: KdfAlgorithm::HkdfSha3_256,
    aead: AeadCipher::Aes256Gcm,
};

// Generate recipient keypair
let kem = MlKem::new(MlKemVariant::MlKem768);
let (pk, sk) = kem.generate_keypair()?;

// Encrypt
let (enc_key, ciphertext) = seal(
    config,
    &pk.to_bytes(),
    b"context info",
    b"secret message",
    b"associated data"
)?;

// Decrypt
let plaintext = open(
    config,
    &sk.to_bytes(),
    &enc_key,
    b"context info",
    &ciphertext,
    b"associated data"
)?;
```

### Complete Quantum-Secure Communication

Combine ML-KEM key exchange with symmetric primitives:

```rust
use saorsa_pqc::api::{ml_kem_768, ChaCha20Poly1305};
use saorsa_pqc::api::symmetric::generate_nonce;

// Alice generates ML-KEM keypair
let kem = ml_kem_768();
let (alice_pk, alice_sk) = kem.generate_keypair()?;

// Bob encapsulates a shared secret using Alice's public key
let (shared_secret, ciphertext) = kem.encapsulate(&alice_pk)?;

// Alice decapsulates to get the same shared secret
let recovered_secret = kem.decapsulate(&alice_sk, &ciphertext)?;

// Derive proper encryption key from shared secret using HKDF
use saorsa_pqc::api::kdf::HkdfSha3_256;
use saorsa_pqc::api::traits::Kdf;

let mut encryption_key = [0u8; 32];
HkdfSha3_256::derive(
    &shared_secret.to_bytes(),
    None,
    b"saorsa-pqc encryption key",
    &mut encryption_key
)?;

// Create cipher with derived key
let cipher = ChaCha20Poly1305::new(&encryption_key);

// Now Bob can encrypt messages to Alice
let nonce = generate_nonce();
let message = b"Quantum-secure message";
let encrypted = cipher.encrypt(&nonce, message)?;

// Alice decrypts using the same key
let decrypted = cipher.decrypt(&nonce, &encrypted)?;
assert_eq!(decrypted, message);
```

## 🛠️ Additional Features

### Serialization

```rust
// All keys and signatures support serialization
let pk_bytes = public_key.to_bytes();
let restored_pk = MlKemPublicKey::from_bytes(
    MlKemVariant::MlKem768, 
    &pk_bytes
)?;
```

### Context Support (ML-DSA)

```rust
// ML-DSA supports domain separation via context
let context = b"application-specific-context";
let signature = dsa.sign_with_context(&secret_key, message, context)?;
let is_valid = dsa.verify_with_context(&public_key, message, &signature, context)?;
```

### Deterministic Key Generation

```rust
// Generate keys from seed (for testing/reproducibility)
// Uses FIPS 203 deterministic generation with two 32-byte seeds
let d_seed = [0u8; 32];  // First seed value
let z_seed = [1u8; 32];  // Second seed value
let kem = ml_kem_768();
let (pk, sk) = kem.generate_keypair_from_seed(&d_seed, &z_seed);

// Deterministic generation produces identical keys
let (pk2, sk2) = kem.generate_keypair_from_seed(&d_seed, &z_seed);
assert_eq!(pk.to_bytes(), pk2.to_bytes());
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/dirvine/saorsa-pqc
cd saorsa-pqc

# Run tests
cargo test --all-features

# Run benchmarks
cargo bench

# Check code quality
cargo clippy --all-features
cargo fmt --check
```

## 📄 License

This project is dual-licensed under:
- MIT License
- Apache License 2.0

Choose whichever license works best for your use case.

## 🙏 Acknowledgments

This library builds upon the excellent work of:
- [fips203](https://crates.io/crates/fips203) - ML-KEM implementation
- [fips204](https://crates.io/crates/fips204) - ML-DSA implementation
- [fips205](https://crates.io/crates/fips205) - SLH-DSA implementation
- [blake3](https://crates.io/crates/blake3) - BLAKE3 hash function
- [sha3](https://crates.io/crates/sha3) - SHA3 and Keccak implementations
- [aes-gcm](https://crates.io/crates/aes-gcm) - AES-GCM AEAD cipher
- [chacha20poly1305](https://crates.io/crates/chacha20poly1305) - ChaCha20-Poly1305 AEAD
- [hkdf](https://crates.io/crates/hkdf) - HMAC-based Key Derivation Function
- [hmac](https://crates.io/crates/hmac) - HMAC implementation

## 📮 Contact

- **Author**: David Irvine
- **Email**: david@saorsalabs.com
- **GitHub**: [@dirvine](https://github.com/dirvine)

## 🚀 Roadmap

- [ ] Hardware security module (HSM) support
- [ ] WebAssembly bindings
- [ ] C FFI bindings
- [ ] Hybrid modes (PQC + Classical)
- [ ] SHAKE256 XOF implementation
- [ ] Additional KDF algorithms (PBKDF2, Argon2)
- [x] **Side-channel resistance validation** ✅ (v0.4.0 - DudeCT integration)
- [ ] Formal verification of critical paths
- [ ] Performance optimizations for specific platforms

---

## 📅 2024 NIST Updates

This library incorporates the latest NIST standards released in 2024:
- **August 13, 2024**: ML-KEM, ML-DSA, and SLH-DSA algorithms enabled on ACVTS Production server
- **FIPS 203, 204, 205**: Final standards published replacing draft versions
- **Test Vectors**: Updated to match the final NIST specifications

**Note**: This library is under active development. While the underlying FIPS implementations are certified, always perform your own security audit before production use.