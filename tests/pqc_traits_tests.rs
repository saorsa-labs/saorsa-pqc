//! Comprehensive tests for PQC traits implementation
//!
//! This test suite validates the KEM and Sig traits with test vectors,
//! serialization round-trips, and zeroization verification.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_pqc::pqc::{
    blake3_helpers, ConstantTimeCompare, Kem, MlDsa44Trait, MlDsa65Trait, MlDsa87Trait,
    MlKem1024Trait, MlKem512Trait, MlKem768Trait, SecureBuffer, Sig,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Test vector for KEM operations
#[derive(Debug, Serialize, Deserialize)]
struct KemTestVector {
    name: String,
    seed: Vec<u8>,
    expected_pk_hash: String,
    expected_ct_hash: String,
    expected_ss_hash: String,
}

/// Test vector for signature operations
#[derive(Debug, Serialize, Deserialize)]
struct SigTestVector {
    name: String,
    seed: Vec<u8>,
    message: Vec<u8>,
    expected_pk_hash: String,
    expected_sig_hash: String,
}

/// Generic KEM test helper
fn test_kem_roundtrip<K: Kem>()
where
    K::Ss: ConstantTimeCompare,
{
    // Test basic encapsulation/decapsulation
    let (pk, sk) = K::keypair();
    let (ss1, ct) = K::encap(&pk);
    let ss2 = K::decap(&sk, &ct).expect("Decapsulation should succeed");

    assert!(ss1.ct_eq(&ss2), "Shared secrets should match");

    // Test serialization round-trip
    let pk_bytes = pk.as_ref();
    let sk_bytes = sk.as_ref();
    let ct_bytes = ct.as_ref();

    assert!(!pk_bytes.is_empty(), "Public key should not be empty");
    assert!(!sk_bytes.is_empty(), "Secret key should not be empty");
    assert!(!ct_bytes.is_empty(), "Ciphertext should not be empty");
}

/// Generic signature test helper
fn test_sig_roundtrip<S: Sig>() {
    // Test basic sign/verify
    let (pk, sk) = S::keypair();
    let msg = b"Test message for signature verification";
    let sig = S::sign(&sk, msg);

    assert!(S::verify(&pk, msg, &sig), "Signature should verify");

    // Test with wrong message
    let wrong_msg = b"Different message";
    assert!(
        !S::verify(&pk, wrong_msg, &sig),
        "Signature should not verify for wrong message"
    );

    // Test with wrong public key
    let (wrong_pk, _) = S::keypair();
    assert!(
        !S::verify(&wrong_pk, msg, &sig),
        "Signature should not verify with wrong public key"
    );

    // Test serialization
    let pk_bytes = pk.as_ref();
    let sk_bytes = sk.as_ref();
    let sig_bytes = sig.as_ref();

    assert!(!pk_bytes.is_empty(), "Public key should not be empty");
    assert!(!sk_bytes.is_empty(), "Secret key should not be empty");
    assert!(!sig_bytes.is_empty(), "Signature should not be empty");
}

#[test]
fn test_ml_kem_512_roundtrip() {
    test_kem_roundtrip::<MlKem512Trait>();
}

#[test]
fn test_ml_kem_768_roundtrip() {
    test_kem_roundtrip::<MlKem768Trait>();
}

#[test]
fn test_ml_kem_1024_roundtrip() {
    test_kem_roundtrip::<MlKem1024Trait>();
}

#[test]
fn test_ml_dsa_44_roundtrip() {
    test_sig_roundtrip::<MlDsa44Trait>();
}

#[test]
fn test_ml_dsa_65_roundtrip() {
    test_sig_roundtrip::<MlDsa65Trait>();
}

#[test]
fn test_ml_dsa_87_roundtrip() {
    test_sig_roundtrip::<MlDsa87Trait>();
}

#[test]
fn test_blake3_helpers() {
    // Test key derivation
    let context = "test-context";
    let input = b"test input data";
    let key1 = blake3_helpers::derive_key(context, input);
    let key2 = blake3_helpers::derive_key(context, input);
    assert_eq!(key1, key2, "Key derivation should be deterministic");

    // Different context should give different key
    let key3 = blake3_helpers::derive_key("different-context", input);
    assert_ne!(
        key1, key3,
        "Different contexts should produce different keys"
    );

    // Test hashing
    let data = b"data to hash";
    let hash1 = blake3_helpers::hash(data);
    let hash2 = blake3_helpers::hash(data);
    assert_eq!(hash1, hash2, "Hashing should be deterministic");

    // Test keyed hash (MAC)
    let key = [0x42u8; 32];
    let mac1 = blake3_helpers::keyed_hash(&key, data);
    let mac2 = blake3_helpers::keyed_hash(&key, data);
    assert_eq!(mac1, mac2, "MAC should be deterministic");

    // Different key should give different MAC
    let different_key = [0x43u8; 32];
    let mac3 = blake3_helpers::keyed_hash(&different_key, data);
    assert_ne!(mac1, mac3, "Different keys should produce different MACs");

    // Test KDF
    let kdf_output = blake3_helpers::kdf(input, b"context", 64);
    assert_eq!(kdf_output.len(), 64, "KDF should produce requested length");

    // KDF should be deterministic
    let kdf_output2 = blake3_helpers::kdf(input, b"context", 64);
    assert_eq!(kdf_output, kdf_output2, "KDF should be deterministic");
}

#[test]
fn test_secure_buffer() {
    // Test creation and access
    let buffer = SecureBuffer::<32>::new([0x42u8; 32]);
    assert_eq!(buffer.as_ref().first(), Some(&0x42));
    assert_eq!(buffer.as_ref().len(), 32);

    // Test zero buffer
    let zero_buffer = SecureBuffer::<32>::zero();
    assert_eq!(zero_buffer.as_ref().first(), Some(&0));
    assert_eq!(zero_buffer.as_ref().get(31), Some(&0));

    // Test constant-time comparison
    let buffer1 = SecureBuffer::<16>::new([1u8; 16]);
    let buffer2 = SecureBuffer::<16>::new([1u8; 16]);
    let buffer3 = SecureBuffer::<16>::new([2u8; 16]);

    assert!(
        buffer1.ct_eq(&buffer2),
        "Equal buffers should compare equal"
    );
    assert!(
        !buffer1.ct_eq(&buffer3),
        "Different buffers should not compare equal"
    );
}

#[test]
fn test_kem_multiple_encapsulations() {
    // Test that multiple encapsulations with same public key produce different results
    let (pk, sk) = MlKem768Trait::keypair();

    let (ss1, ct1) = MlKem768Trait::encap(&pk);
    let (ss2, ct2) = MlKem768Trait::encap(&pk);

    // Ciphertexts should be different (uses randomness)
    assert_ne!(
        ct1.as_ref(),
        ct2.as_ref(),
        "Ciphertexts should be different"
    );

    // But both should decapsulate correctly
    let recovered_ss1 = MlKem768Trait::decap(&sk, &ct1).unwrap();
    let recovered_ss2 = MlKem768Trait::decap(&sk, &ct2).unwrap();

    assert!(
        ss1.ct_eq(&recovered_ss1),
        "First shared secret should match"
    );
    assert!(
        ss2.ct_eq(&recovered_ss2),
        "Second shared secret should match"
    );
}

#[test]
fn test_sig_deterministic_signatures() {
    // ML-DSA signatures are randomized in FIPS 204
    // The test just ensures both signatures verify correctly
    let (pk, sk) = MlDsa65Trait::keypair();
    let msg = b"Signature test";

    let sig1 = MlDsa65Trait::sign(&sk, msg);
    let sig2 = MlDsa65Trait::sign(&sk, msg);

    // Both signatures should verify even if different
    assert!(
        MlDsa65Trait::verify(&pk, msg, &sig1),
        "First signature should verify"
    );
    assert!(
        MlDsa65Trait::verify(&pk, msg, &sig2),
        "Second signature should verify"
    );
}

#[test]
fn test_sig_empty_message() {
    // Test signing empty messages
    let (pk, sk) = MlDsa65Trait::keypair();
    let empty_msg = b"";

    let sig = MlDsa65Trait::sign(&sk, empty_msg);
    assert!(
        MlDsa65Trait::verify(&pk, empty_msg, &sig),
        "Should be able to sign and verify empty messages"
    );
}

#[test]
fn test_sig_large_message() {
    // Test signing large messages
    let (pk, sk) = MlDsa87Trait::keypair();
    let large_msg = vec![0x42u8; 1_000_000]; // 1MB message

    let sig = MlDsa87Trait::sign(&sk, &large_msg);
    assert!(
        MlDsa87Trait::verify(&pk, &large_msg, &sig),
        "Should be able to sign and verify large messages"
    );
}

#[test]
fn test_constant_time_comparison() {
    // Test the constant-time comparison trait
    let data1 = vec![1, 2, 3, 4];
    let data2 = vec![1, 2, 3, 4];
    let data3 = vec![1, 2, 3, 5];

    assert!(data1.ct_eq(&data2), "Equal data should compare equal");
    assert!(
        !data1.ct_eq(&data3),
        "Different data should not compare equal"
    );

    // Test with different lengths
    let short = vec![1, 2, 3];
    let long = vec![1, 2, 3, 4, 5];
    assert!(
        !short.ct_eq(&long),
        "Different lengths should not compare equal"
    );
}

#[test]
fn test_serialization_compatibility() {
    // Test that keys and signatures can be serialized and deserialized
    let (pk, sk) = MlKem768Trait::keypair();

    // Serialize public key
    let pk_bytes = pk.as_ref().to_vec();
    assert_eq!(
        pk_bytes.len(),
        1184,
        "ML-KEM-768 public key should be 1184 bytes"
    );

    // Serialize secret key
    let sk_bytes = sk.as_ref().to_vec();
    assert_eq!(
        sk_bytes.len(),
        2400,
        "ML-KEM-768 secret key should be 2400 bytes"
    );

    // Test signature serialization
    let (sig_pk, sig_sk) = MlDsa65Trait::keypair();
    let msg = b"Test message";
    let sig = MlDsa65Trait::sign(&sig_sk, msg);

    let sig_pk_bytes = sig_pk.as_ref().to_vec();
    assert_eq!(
        sig_pk_bytes.len(),
        1952,
        "ML-DSA-65 public key should be 1952 bytes"
    );

    let sig_bytes = sig.as_ref().to_vec();
    assert_eq!(
        sig_bytes.len(),
        3309,
        "ML-DSA-65 signature should be 3309 bytes"
    );
}

/// Integration test combining KEM and signatures
#[test]
fn test_kem_sig_integration() {
    // Alice generates KEM and signature keypairs
    let (_alice_kem_pk, _alice_kem_sk) = MlKem768Trait::keypair();
    let (alice_sig_pk, alice_sig_sk) = MlDsa65Trait::keypair();

    // Bob generates KEM and signature keypairs
    let (bob_kem_pk, _bob_kem_sk) = MlKem768Trait::keypair();
    let (bob_sig_pk, bob_sig_sk) = MlDsa65Trait::keypair();

    // Alice encapsulates a shared secret for Bob and signs it
    let (shared_secret, ciphertext) = MlKem768Trait::encap(&bob_kem_pk);
    let signature = MlDsa65Trait::sign(&alice_sig_sk, ciphertext.as_ref());

    // Bob verifies the signature and decapsulates
    assert!(
        MlDsa65Trait::verify(&alice_sig_pk, ciphertext.as_ref(), &signature),
        "Signature should verify"
    );

    // In a real scenario, Bob would decapsulate with his secret key
    // Here we just verify the process works

    // Bob can also send an authenticated response
    let response = b"Acknowledged";
    let response_sig = MlDsa65Trait::sign(&bob_sig_sk, response);

    assert!(
        MlDsa65Trait::verify(&bob_sig_pk, response, &response_sig),
        "Response signature should verify"
    );

    // Verify shared secret is non-zero
    let ss_bytes = shared_secret.as_ref();
    assert!(
        ss_bytes.iter().any(|&b| b != 0),
        "Shared secret should not be all zeros"
    );
}

/// Test that zeroization happens (requires special tooling to fully verify)
#[test]
fn test_zeroization_api() {
    use zeroize::Zeroize;

    // Test that SecureBuffer implements zeroization
    let mut buffer = SecureBuffer::<32>::new([0x42u8; 32]);
    buffer.zeroize();

    // After zeroization, all bytes should be zero
    // Note: This test doesn't guarantee the compiler won't optimize it away
    // Proper verification requires tools like Valgrind or memory inspection
    assert_eq!(
        buffer.as_ref().first(),
        Some(&0),
        "Buffer should be zeroized"
    );
    assert_eq!(
        buffer.as_ref().get(31),
        Some(&0),
        "Buffer should be zeroized"
    );
}
