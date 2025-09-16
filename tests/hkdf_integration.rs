//! Integration tests for HKDF (HMAC-based Key Derivation Function)
//!
//! Tests the HKDF implementation with SHA3-256 and SHA3-512 variants
//! to ensure proper key derivation for post-quantum cryptographic applications.

#![cfg(test)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use saorsa_pqc::api::traits::Kdf;
use saorsa_pqc::{kdf_helpers, HkdfSha3_256, HkdfSha3_512, KdfAlgorithm};

#[test]
fn test_hkdf_sha3_256_derive() {
    let ikm = b"initial key material for testing";
    let salt = b"random salt value";
    let info = b"application-specific info";
    let mut okm = [0u8; 32];

    // Test basic derivation
    HkdfSha3_256::derive(ikm, Some(salt), info, &mut okm)
        .expect("HKDF-SHA3-256 derive should succeed");

    // Verify deterministic behavior
    let mut okm2 = [0u8; 32];
    HkdfSha3_256::derive(ikm, Some(salt), info, &mut okm2)
        .expect("Second derivation should succeed");
    assert_eq!(okm, okm2, "HKDF should be deterministic");

    // Test without salt
    let mut okm3 = [0u8; 32];
    HkdfSha3_256::derive(ikm, None, info, &mut okm3)
        .expect("Derivation without salt should succeed");
    assert_ne!(okm, okm3, "Different salt should produce different output");
}

#[test]
fn test_hkdf_sha3_512_derive() {
    let ikm = b"initial key material for SHA3-512";
    let salt = b"salt for SHA3-512";
    let info = b"info for SHA3-512";

    // Test with different output lengths
    let mut okm_64 = [0u8; 64];
    HkdfSha3_512::derive(ikm, Some(salt), info, &mut okm_64)
        .expect("HKDF-SHA3-512 derive should succeed");

    let mut okm_32 = [0u8; 32];
    HkdfSha3_512::derive(ikm, Some(salt), info, &mut okm_32)
        .expect("Derivation with shorter output should succeed");

    // First 32 bytes should match
    assert_eq!(&okm_64[..32], &okm_32[..], "Partial output should match");
}

#[test]
fn test_hkdf_extract_and_expand() {
    let ikm = b"test input key material";
    let salt = b"test salt";
    let info1 = b"context 1";
    let info2 = b"context 2";

    // Extract PRK once
    let prk = HkdfSha3_256::extract(Some(salt), ikm);
    assert_eq!(prk.len(), 32, "PRK should be 32 bytes for SHA3-256");

    // Expand to multiple outputs with different info
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];

    HkdfSha3_256::expand(&prk, info1, &mut okm1).expect("First expand should succeed");
    HkdfSha3_256::expand(&prk, info2, &mut okm2).expect("Second expand should succeed");

    assert_ne!(
        okm1, okm2,
        "Different info should produce different outputs"
    );
}

#[test]
fn test_kdf_algorithm_enum() {
    let ikm = b"key material for enum test";
    let salt = b"enum test salt";
    let info = b"enum test info";

    // Test SHA3-256 variant
    let result_256 = KdfAlgorithm::HkdfSha3_256
        .derive(ikm, Some(salt), info, 32)
        .expect("KdfAlgorithm::HkdfSha3_256 should succeed");
    assert_eq!(result_256.len(), 32);
    assert_eq!(KdfAlgorithm::HkdfSha3_256.name(), "HKDF-SHA3-256");

    // Test SHA3-512 variant
    let result_512 = KdfAlgorithm::HkdfSha3_512
        .derive(ikm, Some(salt), info, 64)
        .expect("KdfAlgorithm::HkdfSha3_512 should succeed");
    assert_eq!(result_512.len(), 64);
    assert_eq!(KdfAlgorithm::HkdfSha3_512.name(), "HKDF-SHA3-512");

    // Outputs should be different
    assert_ne!(&result_256[..], &result_512[..32]);
}

#[test]
fn test_derive_enc_auth_keys() {
    let shared_secret = b"shared secret from ML-KEM key exchange";
    let context = b"TLS 1.3 handshake context";

    let (enc_key, auth_key) = kdf_helpers::derive_enc_auth_keys(shared_secret, context)
        .expect("Deriving enc/auth keys should succeed");

    // Check lengths
    assert_eq!(enc_key.len(), 32, "Encryption key should be 32 bytes");
    assert_eq!(auth_key.len(), 32, "Authentication key should be 32 bytes");

    // Keys should be different
    assert_ne!(
        &enc_key[..],
        &auth_key[..],
        "Encryption and auth keys must be different"
    );

    // Test determinism
    let (enc_key2, auth_key2) = kdf_helpers::derive_enc_auth_keys(shared_secret, context)
        .expect("Second derivation should succeed");
    assert_eq!(&enc_key[..], &enc_key2[..], "Should be deterministic");
    assert_eq!(&auth_key[..], &auth_key2[..], "Should be deterministic");
}

#[test]
fn test_key_stretching() {
    let short_key = b"short";
    let label1 = b"client write key";
    let label2 = b"server write key";

    let stretched1 =
        kdf_helpers::stretch_key(short_key, label1, 48).expect("Key stretching should succeed");
    let stretched2 =
        kdf_helpers::stretch_key(short_key, label2, 48).expect("Key stretching should succeed");

    assert_eq!(stretched1.len(), 48);
    assert_eq!(stretched2.len(), 48);
    assert_ne!(
        stretched1, stretched2,
        "Different labels should give different outputs"
    );
}

#[test]
fn test_key_hierarchy_derivation() {
    let master_key = b"master application key";
    let labels = vec![
        b"encryption".as_slice(),
        b"authentication".as_slice(),
        b"integrity".as_slice(),
        b"key_exchange".as_slice(),
    ];

    let derived_keys = kdf_helpers::derive_key_hierarchy(master_key, &labels)
        .expect("Key hierarchy derivation should succeed");

    assert_eq!(derived_keys.len(), 4, "Should derive 4 keys");

    // All keys should be 32 bytes
    for key in &derived_keys {
        assert_eq!(key.len(), 32);
    }

    // All keys should be unique
    for i in 0..derived_keys.len() {
        for j in (i + 1)..derived_keys.len() {
            assert_ne!(
                &derived_keys[i][..],
                &derived_keys[j][..],
                "All derived keys must be unique"
            );
        }
    }
}

#[test]
fn test_password_key_derivation() {
    let password = b"user_password_123";
    let salt1 = b"random_salt_1";
    let salt2 = b"random_salt_2";
    let iterations = 1000; // Use higher value in production

    let key1 = kdf_helpers::derive_key_from_password(password, salt1, iterations)
        .expect("Password derivation should succeed");
    let key2 = kdf_helpers::derive_key_from_password(password, salt2, iterations)
        .expect("Password derivation should succeed");

    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    assert_ne!(
        &key1[..],
        &key2[..],
        "Different salts should produce different keys"
    );

    // Test with different iteration counts
    let key3 = kdf_helpers::derive_key_from_password(password, salt1, iterations * 2)
        .expect("Password derivation with more iterations should succeed");
    assert_ne!(
        &key1[..],
        &key3[..],
        "Different iterations should produce different keys"
    );
}

#[test]
fn test_hkdf_max_output_length() {
    // HKDF can produce up to 255 * hash_length bytes
    // For SHA3-256, that's 255 * 32 = 8160 bytes
    let ikm = b"test key material";
    let salt = b"test salt";
    let info = b"max length test";

    // Test near maximum for SHA3-256
    let max_len = 255 * 32; // 8160 bytes
    let result = KdfAlgorithm::HkdfSha3_256
        .derive(ikm, Some(salt), info, max_len)
        .expect("Max length derivation should succeed");
    assert_eq!(result.len(), max_len);

    // Test that exceeding max length fails
    let too_long = max_len + 1;
    let result = KdfAlgorithm::HkdfSha3_256.derive(ikm, Some(salt), info, too_long);
    assert!(
        result.is_err(),
        "Should fail when exceeding max output length"
    );
}

#[test]
fn test_hkdf_with_empty_inputs() {
    // Test with empty IKM (should work but not recommended)
    let mut okm = [0u8; 32];
    let result = HkdfSha3_256::derive(b"", Some(b"salt"), b"info", &mut okm);
    assert!(result.is_ok(), "Empty IKM should be accepted");

    // Test with empty salt (common use case)
    let result = HkdfSha3_256::derive(b"ikm", Some(b""), b"info", &mut okm);
    assert!(result.is_ok(), "Empty salt should work");

    // Test with empty info (valid use case)
    let result = HkdfSha3_256::derive(b"ikm", Some(b"salt"), b"", &mut okm);
    assert!(result.is_ok(), "Empty info should work");
}

#[test]
fn test_hkdf_cross_compatibility() {
    // Verify that extract + expand equals derive
    let ikm = b"test input key material";
    let salt = b"test salt value";
    let info = b"test context info";

    // Method 1: Direct derive
    let mut okm1 = [0u8; 64];
    HkdfSha3_512::derive(ikm, Some(salt), info, &mut okm1).expect("Direct derive should succeed");

    // Method 2: Extract then expand
    let prk = HkdfSha3_512::extract(Some(salt), ikm);
    let mut okm2 = [0u8; 64];
    HkdfSha3_512::expand(&prk, info, &mut okm2).expect("Expand should succeed");

    assert_eq!(okm1, okm2, "Extract+Expand should equal Derive");
}
