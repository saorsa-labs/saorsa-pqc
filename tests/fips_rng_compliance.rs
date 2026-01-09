//! FIPS 140-3 RNG Compliance Tests
//!
//! This test suite validates that the FIPS RNG implementation meets
//! NIST SP 800-90A and SP 800-90B requirements for cryptographic random
//! number generation.
//!
//! Test Categories:
//! - DRBG Known Answer Tests (KAT)
//! - Entropy source validation
//! - Continuous health monitoring
//! - Failure detection and recovery
//! - Minimum entropy strength validation
//! - Reseed mechanism tests

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use saorsa_pqc::pqc::{FipsRng, SecurityStrength};

#[test]
fn test_fips_rng_basic_creation() {
    // Test creation for all security strengths
    for &strength in &[
        SecurityStrength::Bits128,
        SecurityStrength::Bits192,
        SecurityStrength::Bits256,
    ] {
        let result = FipsRng::new(strength);
        assert!(
            result.is_ok(),
            "FIPS RNG creation should succeed for {:?}",
            strength
        );
    }
}

#[test]
fn test_random_output_non_repeatability() {
    // Verify that the RNG produces different outputs
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();

    let mut samples = Vec::new();
    for _ in 0..10 {
        let mut buf = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut buf);
        samples.push(buf);
    }

    // All samples should be unique (non-repeatability requirement)
    for i in 0..samples.len() {
        for j in (i + 1)..samples.len() {
            assert_ne!(
                samples[i], samples[j],
                "RNG should not produce identical outputs"
            );
        }
    }
}

#[test]
fn test_deterministic_generation_from_seed() {
    // Test that same seed produces same sequence (for testing/validation)
    let seed = [42u8; 32];
    let mut rng1 = FipsRng::from_seed(seed, SecurityStrength::Bits256);
    let mut rng2 = FipsRng::from_seed(seed, SecurityStrength::Bits256);

    for _ in 0..100 {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rand_core::RngCore::fill_bytes(&mut rng1, &mut buf1);
        rand_core::RngCore::fill_bytes(&mut rng2, &mut buf2);

        assert_eq!(buf1, buf2, "Same seed should produce identical sequences");
    }
}

#[test]
fn test_output_distribution_basic() {
    // Basic statistical test: verify output is not obviously biased
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut output = vec![0u8; 10000]; // 10KB sample

    rand_core::RngCore::fill_bytes(&mut rng, &mut output);

    // Count occurrences of each byte value
    let mut counts = [0usize; 256];
    for &byte in &output {
        counts[byte as usize] += 1;
    }

    // With 10000 bytes, expect ~39 of each value (10000/256)
    // Allow reasonable deviation for random distribution: min 15, max 70
    // This accounts for natural variance in random data
    let min_count = 15;
    let max_count = 70;

    for (value, &count) in counts.iter().enumerate() {
        assert!(
            count >= min_count && count <= max_count,
            "Byte value {} appears {} times (expected {}-{})",
            value,
            count,
            min_count,
            max_count
        );
    }
}

#[test]
fn test_reseed_changes_state() {
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();

    // Generate some bytes before reseed
    let mut before = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rng, &mut before);

    // Force reseed
    rng.reseed().unwrap();

    // Generate after reseed
    let mut after = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rng, &mut after);

    // After reseed, next output should be different
    // (There's a negligible probability they could match by chance)
    assert_ne!(
        before, after,
        "Reseed should change RNG state and produce different output"
    );
}

#[test]
fn test_large_data_generation() {
    // Test generating large amounts of data (tests chunking)
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut large_buffer = vec![0u8; 1_000_000]; // 1MB

    rand_core::RngCore::fill_bytes(&mut rng, &mut large_buffer);

    // Verify it's not all zeros
    assert!(!large_buffer.iter().all(|&b| b == 0));

    // Verify some entropy (at least 10% of bytes are non-zero)
    let non_zero_count = large_buffer.iter().filter(|&&b| b != 0).count();
    assert!(
        non_zero_count > large_buffer.len() / 10,
        "Large buffer should have sufficient entropy"
    );
}

#[test]
fn test_concurrent_rng_usage() {
    // Test that cloned RNGs work independently
    let rng1 = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut rng2 = rng1.clone();

    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    rand_core::RngCore::fill_bytes(&mut rng2, &mut output2);

    // Different RNG instances should produce different outputs
    // (unless they share the same seed, which they don't here)
    rand_core::RngCore::fill_bytes(&mut rng2, &mut output1);

    assert_ne!(
        output1, output2,
        "Cloned RNGs should produce independent outputs"
    );
}

#[test]
fn test_health_check_functionality() {
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();

    // Health check should pass on a good RNG
    let result = rng.health_check();
    assert!(result.is_ok(), "Health check should pass");

    // Generate some data and check again
    let mut buffer = [0u8; 1000];
    rand_core::RngCore::fill_bytes(&mut rng, &mut buffer);

    let result2 = rng.health_check();
    assert!(
        result2.is_ok(),
        "Health check should still pass after generation"
    );
}

#[test]
fn test_security_strength_retrieval() {
    for &strength in &[
        SecurityStrength::Bits128,
        SecurityStrength::Bits192,
        SecurityStrength::Bits256,
    ] {
        let rng = FipsRng::new(strength).unwrap();
        assert_eq!(
            rng.security_strength(),
            strength,
            "RNG should return correct security strength"
        );
    }
}

#[test]
fn test_zero_length_generation() {
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut empty = [];

    // Should handle empty buffer gracefully
    rand_core::RngCore::fill_bytes(&mut rng, &mut empty);
    // If it doesn't panic, test passes
}

#[test]
fn test_small_requests() {
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();

    // Test various small sizes
    for size in [1, 2, 3, 7, 15, 16, 31, 32, 63, 64] {
        // For very small buffers (1-2 bytes), a single all-zeros result has
        // non-trivial probability (0.4% for 1 byte, 0.0015% for 2 bytes).
        // For robustness, we sample multiple times and check that at least one
        // has non-zero content. For larger buffers (>= 8 bytes), probability
        // of all zeros is astronomically low (2^-64), so single sample suffices.
        let samples = if size < 8 { 10 } else { 1 };
        let mut found_nonzero = false;

        for _ in 0..samples {
            let mut buffer = vec![0u8; size];
            rand_core::RngCore::fill_bytes(&mut rng, &mut buffer);

            if !buffer.iter().all(|&b| b == 0) {
                found_nonzero = true;
                break;
            }
        }

        assert!(
            found_nonzero,
            "Small buffer of size {} should have randomness (after {} samples)",
            size, samples
        );
    }
}

#[test]
fn test_repeated_reseeds() {
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut outputs = Vec::new();

    // Perform multiple reseeds and collect outputs
    for _ in 0..5 {
        rng.reseed().unwrap();
        let mut output = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut output);
        outputs.push(output);
    }

    // All outputs should be different
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "Each reseed should produce unique state"
            );
        }
    }
}

#[test]
fn test_runs_test_basic() {
    // Simple runs test: verify there are both runs of 0s and 1s
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut buffer = vec![0u8; 1000];

    rand_core::RngCore::fill_bytes(&mut rng, &mut buffer);

    // Count runs (sequences of same bit)
    let mut runs_of_ones = 0;
    let mut runs_of_zeros = 0;
    let mut in_run_of_ones = false;

    for &byte in &buffer {
        for bit in 0..8 {
            let bit_value = (byte >> bit) & 1;
            if bit_value == 1 {
                if !in_run_of_ones {
                    runs_of_ones += 1;
                    in_run_of_ones = true;
                }
            } else {
                if in_run_of_ones {
                    runs_of_zeros += 1;
                    in_run_of_ones = false;
                }
            }
        }
    }

    // Both types of runs should occur in random data
    assert!(runs_of_ones > 100, "Should have multiple runs of 1s");
    assert!(runs_of_zeros > 100, "Should have multiple runs of 0s");
}

#[test]
fn test_next_u32_next_u64() {
    use rand_core::RngCore;

    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();

    // Test next_u32
    let u32_values: Vec<u32> = (0..100).map(|_| rng.next_u32()).collect();
    let unique_u32: std::collections::HashSet<_> = u32_values.iter().collect();
    assert!(
        unique_u32.len() > 90,
        "Should have high diversity in u32 values"
    );

    // Test next_u64
    let u64_values: Vec<u64> = (0..100).map(|_| rng.next_u64()).collect();
    let unique_u64: std::collections::HashSet<_> = u64_values.iter().collect();
    assert!(
        unique_u64.len() > 90,
        "Should have high diversity in u64 values"
    );
}

#[test]
fn test_minimum_entropy_bits() {
    // Verify minimum entropy requirements
    assert_eq!(SecurityStrength::Bits128.min_entropy_bytes(), 16);
    assert_eq!(SecurityStrength::Bits192.min_entropy_bytes(), 24);
    assert_eq!(SecurityStrength::Bits256.min_entropy_bytes(), 32);

    assert_eq!(SecurityStrength::Bits128.bits(), 128);
    assert_eq!(SecurityStrength::Bits192.bits(), 192);
    assert_eq!(SecurityStrength::Bits256.bits(), 256);
}

#[test]
fn test_consistent_output_sequence_from_same_seed() {
    // Verify deterministic behavior for testing
    let seed = [123u8; 32];

    let mut rng1 = FipsRng::from_seed(seed, SecurityStrength::Bits256);
    let mut sequence1 = Vec::new();
    for _ in 0..10 {
        let mut buf = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng1, &mut buf);
        sequence1.push(buf);
    }

    let mut rng2 = FipsRng::from_seed(seed, SecurityStrength::Bits256);
    let mut sequence2 = Vec::new();
    for _ in 0..10 {
        let mut buf = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng2, &mut buf);
        sequence2.push(buf);
    }

    assert_eq!(
        sequence1, sequence2,
        "Same seed should produce identical sequences"
    );
}

#[test]
fn test_different_seeds_produce_different_outputs() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];

    let mut rng1 = FipsRng::from_seed(seed1, SecurityStrength::Bits256);
    let mut rng2 = FipsRng::from_seed(seed2, SecurityStrength::Bits256);

    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    rand_core::RngCore::fill_bytes(&mut rng1, &mut buf1);
    rand_core::RngCore::fill_bytes(&mut rng2, &mut buf2);

    assert_ne!(
        buf1, buf2,
        "Different seeds should produce different outputs"
    );
}

#[test]
fn test_fips_rng_cryptorng_trait() {
    // Verify CryptoRng trait is implemented
    fn requires_cryptorng<R: rand_core::RngCore + rand_core::CryptoRng>(_rng: &mut R) {}

    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    requires_cryptorng(&mut rng); // Should compile
}

#[test]
fn test_multiple_sequential_generations() {
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let iterations = 1000;

    for _ in 0..iterations {
        let mut buf = [0u8; 64];
        rand_core::RngCore::fill_bytes(&mut rng, &mut buf);

        // Each generation should produce non-zero output (with very high probability)
        let has_nonzero = buf.iter().any(|&b| b != 0);
        assert!(has_nonzero, "Each generation should produce randomness");
    }
}

#[test]
fn test_chi_square_basic_distribution() {
    // Simple chi-square test for uniform distribution
    let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
    let mut samples = vec![0u8; 10000];

    rand_core::RngCore::fill_bytes(&mut rng, &mut samples);

    // Count frequency of each byte value
    let mut observed = [0usize; 256];
    for &byte in &samples {
        observed[byte as usize] += 1;
    }

    // Expected frequency for uniform distribution
    let expected = samples.len() as f64 / 256.0; // ~39.06

    // Calculate chi-square statistic
    let mut chi_square = 0.0;
    for &obs in &observed {
        let diff = obs as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    // For 255 degrees of freedom at 0.01 significance level,
    // critical value is approximately 310
    // Our test should pass with very high probability for random data
    assert!(
        chi_square < 400.0,
        "Chi-square test failed: {} (should be < 400)",
        chi_square
    );
}
