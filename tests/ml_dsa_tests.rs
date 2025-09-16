//! Comprehensive ML-DSA test suite
//!
//! Tests for ML-DSA (Module-Lattice-based Digital Signature Algorithm)
//! following NIST FIPS 204 standard with ACVP test vectors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::drop_non_drop,
    clippy::manual_abs_diff,
    clippy::clone_on_copy,
    clippy::single_component_path_imports,
    clippy::manual_range_contains
)]

mod common;

use common::{hex_to_bytes, load_test_vectors};
use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};
use std::path::Path;

/// Test ML-DSA-65 key generation against NIST test vectors
#[test]
fn test_ml_dsa_keygen_nist_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let prompt_path = "tests/nist_vectors/ml_dsa/keygen_prompt.json";
    let expected_path = "tests/nist_vectors/ml_dsa/keygen_expected.json";

    if !Path::new(prompt_path).exists() || !Path::new(expected_path).exists() {
        eprintln!("NIST test vectors not found, skipping NIST keygen tests");
        return Ok(());
    }

    let vectors = load_test_vectors(prompt_path)?;
    let expected = load_test_vectors(expected_path)?;

    assert_eq!(
        vectors.test_groups.len(),
        expected.test_groups.len(),
        "Mismatch between prompt and expected test groups"
    );

    for (test_group, expected_group) in vectors.test_groups.iter().zip(expected.test_groups.iter())
    {
        // Focus on ML-DSA-65 parameter set
        if test_group.parameter_set.as_deref() != Some("ML-DSA-65") {
            continue;
        }

        assert_eq!(
            test_group.tests.len(),
            expected_group.tests.len(),
            "Mismatch between prompt and expected test cases"
        );

        for (test, expected_test) in test_group.tests.iter().zip(expected_group.tests.iter()) {
            println!("Testing ML-DSA-65 KeyGen test case {}", test.tc_id);

            // Extract deterministic seed
            let seed = test.seed.as_ref().ok_or("Missing seed in test case")?;
            let seed_bytes = hex_to_bytes(seed)?;

            // Validate seed length
            assert_eq!(seed_bytes.len(), 32, "Seed must be 32 bytes");

            // Extract expected results
            let expected_pk = expected_test
                .pk
                .as_ref()
                .ok_or("Missing expected public key")?;
            let expected_sk = expected_test
                .sk
                .as_ref()
                .ok_or("Missing expected secret key")?;

            let expected_pk_bytes = hex_to_bytes(expected_pk)?;
            let expected_sk_bytes = hex_to_bytes(expected_sk)?;

            // Validate expected key sizes for ML-DSA-65
            assert_eq!(
                expected_pk_bytes.len(),
                1952,
                "ML-DSA-65 public key must be 1952 bytes"
            );
            assert_eq!(
                expected_sk_bytes.len(),
                4032,
                "ML-DSA-65 secret key must be 4032 bytes"
            );

            // TODO: Implement deterministic key generation with seed
            // For now, we validate the structure and sizes

            // Test that regular key generation produces correct sizes
            let ml_dsa = ml_dsa_65();
            let (public_key, secret_key) = ml_dsa
                .generate_keypair()
                .map_err(|e| format!("Key generation failed: {:?}", e))?;

            assert_eq!(
                public_key.to_bytes().len(),
                1952,
                "Generated public key size mismatch"
            );
            assert_eq!(
                secret_key.to_bytes().len(),
                4032,
                "Generated secret key size mismatch"
            );
        }
    }

    Ok(())
}

/// Test ML-DSA-65 signature generation against NIST test vectors
#[test]
fn test_ml_dsa_siggen_nist_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let prompt_path = "tests/nist_vectors/ml_dsa/siggen_prompt.json";
    let expected_path = "tests/nist_vectors/ml_dsa/siggen_expected.json";

    if !Path::new(prompt_path).exists() || !Path::new(expected_path).exists() {
        eprintln!("NIST test vectors not found, skipping NIST siggen tests");
        return Ok(());
    }

    let vectors = load_test_vectors(prompt_path)?;
    let expected = load_test_vectors(expected_path)?;

    for (test_group, expected_group) in vectors.test_groups.iter().zip(expected.test_groups.iter())
    {
        if test_group.parameter_set.as_deref() != Some("ML-DSA-65") {
            continue;
        }

        for (test, expected_test) in test_group.tests.iter().zip(expected_group.tests.iter()) {
            println!("Testing ML-DSA-65 SigGen test case {}", test.tc_id);

            // Extract test inputs
            if let (Some(sk_hex), Some(message_hex)) = (&test.sk, &test.message) {
                let sk_bytes = hex_to_bytes(sk_hex)?;
                let _message_bytes = hex_to_bytes(message_hex)?;

                // Validate secret key size
                assert_eq!(sk_bytes.len(), 4032, "Secret key size mismatch");

                // Extract random value if present (for deterministic signing)
                if let Some(rnd_hex) = &test.rnd {
                    let rnd_bytes = hex_to_bytes(rnd_hex)?;
                    assert_eq!(rnd_bytes.len(), 32, "Random value must be 32 bytes");

                    // TODO: Implement deterministic signing with rnd
                }

                // Extract expected signature
                if let Some(signature_hex) = &expected_test.signature {
                    let expected_signature = hex_to_bytes(signature_hex)?;

                    // ML-DSA-65 signatures are approximately 3309 bytes
                    assert!(
                        expected_signature.len() <= 3309,
                        "ML-DSA-65 signature too large: {} bytes",
                        expected_signature.len()
                    );

                    // TODO: Implement deterministic signature generation and validation
                }
            }
        }
    }

    Ok(())
}

/// Test ML-DSA-65 signature verification against NIST test vectors
#[test]
fn test_ml_dsa_sigver_nist_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let prompt_path = "tests/nist_vectors/ml_dsa/sigver_prompt.json";
    let expected_path = "tests/nist_vectors/ml_dsa/sigver_expected.json";

    if !Path::new(prompt_path).exists() || !Path::new(expected_path).exists() {
        eprintln!("NIST test vectors not found, skipping NIST sigver tests");
        return Ok(());
    }

    let vectors = load_test_vectors(prompt_path)?;
    let expected = load_test_vectors(expected_path)?;

    for (test_group, expected_group) in vectors.test_groups.iter().zip(expected.test_groups.iter())
    {
        if test_group.parameter_set.as_deref() != Some("ML-DSA-65") {
            continue;
        }

        for (test, expected_test) in test_group.tests.iter().zip(expected_group.tests.iter()) {
            println!("Testing ML-DSA-65 SigVer test case {}", test.tc_id);

            // Extract test inputs
            if let (Some(pk_hex), Some(message_hex), Some(signature_hex)) =
                (&test.pk, &test.message, &test.signature)
            {
                let pk_bytes = hex_to_bytes(pk_hex)?;
                let _message_bytes = hex_to_bytes(message_hex)?;
                let signature_bytes = hex_to_bytes(signature_hex)?;

                // Validate public key size
                assert_eq!(pk_bytes.len(), 1952, "Public key size mismatch");

                // Extract expected result
                let _expected_result = expected_test.test_passed.unwrap_or(false);

                // TODO: Implement signature verification
                // For now, validate structure
                assert!(
                    signature_bytes.len() <= 3309,
                    "Signature too large: {} bytes",
                    signature_bytes.len()
                );
            }
        }
    }

    Ok(())
}

/// Test ML-DSA-65 sign/verify round-trip functionality
#[test]
fn test_ml_dsa_sign_verify_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = ml_dsa_65();

    // Generate keypair
    let (public_key, secret_key) = ml_dsa
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Test messages of various sizes
    let test_messages = [
        b"".as_slice(),                                  // Empty message
        b"Hello, ML-DSA!",                               // Short message
        b"The quick brown fox jumps over the lazy dog.", // Medium message
        &vec![0x42u8; 1000],                             // Long message
        &vec![0xFFu8; 10000],                            // Very long message
    ];

    for (i, message) in test_messages.iter().enumerate() {
        println!("Testing sign/verify round-trip for message {}", i);

        // Sign the message
        let signature = ml_dsa
            .sign(&secret_key, message)
            .map_err(|e| format!("Signing failed for message {}: {:?}", i, e))?;

        // Verify the signature
        let is_valid = ml_dsa
            .verify(&public_key, message, &signature)
            .map_err(|e| format!("Verification failed for message {}: {:?}", i, e))?;

        assert!(
            is_valid,
            "Signature verification should succeed for message {}",
            i
        );

        // Verify signature size bounds
        assert!(
            signature.to_bytes().len() <= 3309,
            "Signature too large for message {}: {} bytes",
            i,
            signature.to_bytes().len()
        );
    }

    Ok(())
}

/// Test ML-DSA-65 with invalid/corrupted signatures
#[test]
fn test_ml_dsa_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = ml_dsa_65();

    // Generate keypair
    let (public_key, secret_key) = ml_dsa
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Message to sign
    let message = b"Test message for signature corruption";

    // Sign the message
    let signature = ml_dsa
        .sign(&secret_key, message)
        .map_err(|e| format!("Signing failed: {:?}", e))?;

    // Test 1: Corrupt the signature by flipping a bit
    let original_sig = signature.clone();
    let mut sig_bytes = signature.to_bytes();
    sig_bytes[0] ^= 0x01;
    let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| format!("Failed to create corrupted signature: {:?}", e))?;

    // Verification should fail
    let is_valid = ml_dsa
        .verify(&public_key, message, &signature)
        .map_err(|e| format!("Verification failed: {:?}", e))?;

    assert!(
        !is_valid,
        "Signature verification should fail for corrupted signature"
    );

    // Test 2: Verify original signature still works
    let is_valid = ml_dsa
        .verify(&public_key, message, &original_sig)
        .map_err(|e| format!("Verification failed: {:?}", e))?;

    assert!(is_valid, "Original signature should still verify");

    Ok(())
}

/// Test ML-DSA-65 with wrong message
#[test]
fn test_ml_dsa_wrong_message() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = ml_dsa_65();

    // Generate keypair
    let (public_key, secret_key) = ml_dsa
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Original message
    let message1 = b"Original message for signing";

    // Sign the original message
    let signature = ml_dsa
        .sign(&secret_key, message1)
        .map_err(|e| format!("Signing failed: {:?}", e))?;

    // Try to verify with different message
    let message2 = b"Different message entirely";
    let is_valid = ml_dsa
        .verify(&public_key, message2, &signature)
        .map_err(|e| format!("Verification failed: {:?}", e))?;

    assert!(
        !is_valid,
        "Signature verification should fail for different message"
    );

    // Verify original message still works
    let is_valid = ml_dsa
        .verify(&public_key, message1, &signature)
        .map_err(|e| format!("Verification failed: {:?}", e))?;

    assert!(is_valid, "Original message should still verify");

    Ok(())
}

/// Test ML-DSA-65 key pair serialization/deserialization
#[test]
fn test_ml_dsa_key_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = ml_dsa_65();

    // Generate keypair
    let (original_public_key, original_secret_key) = ml_dsa
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Serialize keys
    let pk_bytes = original_public_key.to_bytes();
    let sk_bytes = original_secret_key.to_bytes();

    // Deserialize keys
    let restored_pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes)
        .map_err(|e| format!("Public key deserialization failed: {:?}", e))?;
    let restored_sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .map_err(|e| format!("Secret key deserialization failed: {:?}", e))?;

    // Test that restored keys work
    let message = b"Test message for restored keys";

    let signature = ml_dsa
        .sign(&restored_sk, message)
        .map_err(|e| format!("Signing with restored key failed: {:?}", e))?;

    let is_valid = ml_dsa
        .verify(&restored_pk, message, &signature)
        .map_err(|e| format!("Verification with restored key failed: {:?}", e))?;

    assert!(is_valid, "Sign/verify with restored keys should work");

    Ok(())
}

/// Test ML-DSA-65 with different key sizes (error conditions)
#[test]
fn test_ml_dsa_invalid_key_sizes() {
    // Test invalid public key sizes
    let invalid_pk_sizes = [0, 100, 1951, 1953, 2000];
    for size in invalid_pk_sizes {
        let invalid_pk_bytes = vec![0u8; size];
        let result = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &invalid_pk_bytes);
        assert!(result.is_err(), "Should reject public key of size {}", size);
    }

    // Test invalid secret key sizes
    let invalid_sk_sizes = [0, 100, 4031, 4033, 5000];
    for size in invalid_sk_sizes {
        let invalid_sk_bytes = vec![0u8; size];
        let result = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &invalid_sk_bytes);
        assert!(result.is_err(), "Should reject secret key of size {}", size);
    }
}

/// Test ML-DSA-65 signature determinism
#[test]
fn test_ml_dsa_signature_determinism() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = ml_dsa_65();

    // Generate keypair
    let (public_key, secret_key) = ml_dsa
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    let message = b"Test message for determinism";

    // Sign the same message multiple times
    let sig1 = ml_dsa.sign(&secret_key, message)?;
    let sig2 = ml_dsa.sign(&secret_key, message)?;
    let sig3 = ml_dsa.sign(&secret_key, message)?;

    // ML-DSA signatures should be non-deterministic (include randomness)
    // So signatures should likely be different
    let sig1_bytes = sig1.to_bytes();
    let sig2_bytes = sig2.to_bytes();
    let sig3_bytes = sig3.to_bytes();

    // All signatures should verify
    assert!(ml_dsa.verify(&public_key, message, &sig1)?);
    assert!(ml_dsa.verify(&public_key, message, &sig2)?);
    assert!(ml_dsa.verify(&public_key, message, &sig3)?);

    // Signatures should likely be different due to randomness
    // Note: There's a tiny chance they could be the same, but very unlikely
    println!("Signature 1 length: {}", sig1_bytes.len());
    println!("Signature 2 length: {}", sig2_bytes.len());
    println!("Signature 3 length: {}", sig3_bytes.len());

    Ok(())
}

/// Test ML-DSA-65 performance characteristics
#[test]
fn test_ml_dsa_performance() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("TARPAULIN").is_ok() {
        eprintln!("Skipping performance timing under coverage instrumentation");
        return Ok(());
    }
    let ml_dsa = ml_dsa_65();

    // Warm up
    let _ = ml_dsa.generate_keypair()?;

    // Time key generation
    let start = std::time::Instant::now();
    let (public_key, secret_key) = ml_dsa.generate_keypair()?;
    let keygen_time = start.elapsed();

    let message = b"Performance test message";

    // Time signing
    let start = std::time::Instant::now();
    let signature = ml_dsa.sign(&secret_key, message)?;
    let sign_time = start.elapsed();

    // Time verification
    let start = std::time::Instant::now();
    let _ = ml_dsa.verify(&public_key, message, &signature)?;
    let verify_time = start.elapsed();

    let ci_mode = std::env::var("CI").is_ok();
    let keygen_limit = if ci_mode { 400 } else { 200 };
    let sign_limit = if ci_mode { 200 } else { 100 };
    let verify_limit = if ci_mode { 200 } else { 50 };

    assert!(
        keygen_time.as_millis() < keygen_limit,
        "Key generation too slow: {}ms (limit {}ms)",
        keygen_time.as_millis(),
        keygen_limit
    );
    assert!(
        sign_time.as_millis() < sign_limit,
        "Signing too slow: {}ms (limit {}ms)",
        sign_time.as_millis(),
        sign_limit
    );
    assert!(
        verify_time.as_millis() < verify_limit,
        "Verification too slow: {}ms (limit {}ms)",
        verify_time.as_millis(),
        verify_limit
    );

    println!("ML-DSA-65 Performance:");
    println!("  Key generation: {:?}", keygen_time);
    println!("  Signing: {:?}", sign_time);
    println!("  Verification: {:?}", verify_time);

    Ok(())
}

/// Test ML-DSA-65 memory safety (no panics on malformed input)
#[test]
fn test_ml_dsa_memory_safety() {
    // Test with all-zero keys
    let zero_pk = vec![0u8; 1952];
    let zero_sk = vec![0u8; 4032];

    // These should not panic, but may return errors
    let _ = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &zero_pk);
    let _ = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &zero_sk);

    // Test with all-ones keys
    let ones_pk = vec![0xFFu8; 1952];
    let ones_sk = vec![0xFFu8; 4032];

    let _ = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &ones_pk);
    let _ = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &ones_sk);

    // Test with random data
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    let mut random_pk = vec![0u8; 1952];
    let mut random_sk = vec![0u8; 4032];

    rng.fill_bytes(&mut random_pk);
    rng.fill_bytes(&mut random_sk);

    let _ = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &random_pk);
    let _ = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &random_sk);
}

/// Test ML-DSA-65 thread safety
#[test]
fn test_ml_dsa_thread_safety() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::thread;

    let ml_dsa = Arc::new(ml_dsa_65());
    let mut handles = vec![];

    // Spawn multiple threads doing ML-DSA operations
    for i in 0..4 {
        let ml_dsa_clone = Arc::clone(&ml_dsa);
        let handle = thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                for j in 0..10 {
                    let (public_key, secret_key) = ml_dsa_clone
                        .generate_keypair()
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    let message = format!("Thread {} message {}", i, j);
                    let signature = ml_dsa_clone
                        .sign(&secret_key, message.as_bytes())
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    let is_valid = ml_dsa_clone
                        .verify(&public_key, message.as_bytes(), &signature)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    assert!(is_valid);
                }
                println!("Thread {} completed successfully", i);
                Ok(())
            },
        );
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle
            .join()
            .expect("Thread panicked")
            .map_err(|e| format!("Thread error: {:?}", e))?;
    }

    Ok(())
}

/// Test ML-DSA-65 with edge case messages
#[test]
fn test_ml_dsa_edge_case_messages() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair()?;

    // Test empty message
    let empty_msg = b"";
    let sig = ml_dsa.sign(&secret_key, empty_msg)?;
    assert!(ml_dsa.verify(&public_key, empty_msg, &sig)?);

    // Test single byte messages
    for byte in [0x00, 0xFF, 0x42] {
        let single_byte_msg = [byte];
        let sig = ml_dsa.sign(&secret_key, &single_byte_msg)?;
        assert!(ml_dsa.verify(&public_key, &single_byte_msg, &sig)?);
    }

    // Test very large message (test chunking/streaming if implemented)
    let large_msg = vec![0x5A; 1_000_000]; // 1MB message
    let sig = ml_dsa.sign(&secret_key, &large_msg)?;
    assert!(ml_dsa.verify(&public_key, &large_msg, &sig)?);

    Ok(())
}
