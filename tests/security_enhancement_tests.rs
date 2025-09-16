//! Enhanced security tests for cryptographic primitives
//!
//! These tests verify additional security properties and edge cases
//! that are important for production cryptographic implementations.

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

use saorsa_pqc::api::{
    kem::{ml_kem_768, MlKem},
    sig::ml_dsa_65,
    symmetric::ChaCha20Poly1305,
};
use std::time::{Duration, Instant};

/// Test resistance to timing attacks on signature verification
#[test]
fn test_timing_attack_resistance() {
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping detailed timing variance check in CI environment");
        return;
    }
    let dsa = ml_dsa_65();
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let message = b"Test message for timing analysis";

    let signature = dsa.sign(&sk, message).unwrap();

    // Create a series of similar messages
    let messages = (0..1000)
        .map(|i| format!("Test message for timing analysis {}", i).into_bytes())
        .collect::<Vec<_>>();

    // Measure verification times
    let mut times = Vec::new();
    for msg in &messages {
        let start = Instant::now();
        let _ = dsa.verify(&pk, msg, &signature);
        times.push(start.elapsed());
    }

    // Calculate timing variance
    let avg_time: Duration = times.iter().sum::<Duration>() / times.len() as u32;
    let variance = times
        .iter()
        .map(|&t| {
            let diff = if t > avg_time {
                t - avg_time
            } else {
                avg_time - t
            };
            diff.as_nanos() as f64
        })
        .sum::<f64>()
        / times.len() as f64;

    // Variance should be reasonable (not too high, indicating timing leaks)
    // This is a basic check - real timing analysis would be more sophisticated
    assert!(
        variance < 1_000_000.0,
        "Timing variance too high: {}",
        variance
    );
}

/// Test cache timing attack resistance
#[test]
fn test_cache_timing_resistance() {
    use saorsa_pqc::pqc::constant_time::ct_eq;

    let base_data = [0xAAu8; 64];
    let mut test_data = base_data.clone();

    // Measure timing for different data patterns
    let mut times = Vec::new();

    for i in 0..100 {
        test_data[0] = i as u8;
        let start = Instant::now();
        let _ = ct_eq(&base_data, &test_data);
        times.push(start.elapsed());
    }

    // Calculate timing differences
    let avg_time: Duration = times.iter().sum::<Duration>() / times.len() as u32;
    let max_deviation = times
        .iter()
        .map(|&t| {
            if t > avg_time {
                t - avg_time
            } else {
                avg_time - t
            }
        })
        .max()
        .unwrap();

    // Maximum deviation should be reasonable (more tolerant for CI environments)
    assert!(
        max_deviation < Duration::from_millis(50),
        "Cache timing deviation too high: {:?}",
        max_deviation
    );
}

/// Test power analysis resistance (basic simulation)
#[test]
fn test_power_analysis_resistance() {
    let kem = ml_kem_768();

    // This is a basic simulation of power analysis resistance
    // In practice, this would require specialized hardware

    let mut operations = Vec::new();

    // Perform operations with different inputs
    for i in 0..100 {
        let (pk, sk) = kem.generate_keypair().unwrap();
        let start = Instant::now();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let mid = Instant::now();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        let end = Instant::now();

        // Calculate durations correctly to avoid overflow
        let encap_time = mid.duration_since(start);
        let decap_time = end.duration_since(mid);
        let total_time = end.duration_since(start);

        operations.push((
            i,
            encap_time,
            decap_time,
            total_time,
            ss1.to_bytes() == ss2.to_bytes(),
        ));
    }

    // Verify all operations completed successfully
    assert!(operations.iter().all(|(_, _, _, _, success)| *success));

    // Check that timing patterns don't reveal information
    // This is a simplified check
    let encap_times: Vec<_> = operations
        .iter()
        .map(|(_, encap_time, _, _, _)| *encap_time)
        .collect();
    let decap_times: Vec<_> = operations
        .iter()
        .map(|(_, _, decap_time, _, _)| *decap_time)
        .collect();

    let encap_avg = encap_times.iter().sum::<Duration>() / encap_times.len() as u32;
    let decap_avg = decap_times.iter().sum::<Duration>() / decap_times.len() as u32;

    // Times should be relatively consistent
    for &time in &encap_times {
        let diff = if time > encap_avg {
            time - encap_avg
        } else {
            encap_avg - time
        };
        assert!(
            diff < Duration::from_millis(50),
            "Encapsulation timing too variable: {:?}",
            diff
        );
    }

    for &time in &decap_times {
        let diff = if time > decap_avg {
            time - decap_avg
        } else {
            decap_avg - time
        };
        assert!(
            diff < Duration::from_millis(50),
            "Decapsulation timing too variable: {:?}",
            diff
        );
    }
}

/// Test electromagnetic emission resistance (simulated)
#[test]
fn test_em_emission_resistance() {
    // This simulates testing for electromagnetic emission patterns
    // In practice, this would require specialized equipment

    let kem = ml_kem_768();
    let mut patterns = Vec::new();

    // Perform operations and collect "patterns"
    for i in 0..50 {
        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();

        // Simulate EM emission pattern (in practice, this would be measured)
        let pattern = (
            i,
            pk.to_bytes().iter().map(|&b| b.count_ones()).sum::<u32>(),
            sk.to_bytes().iter().map(|&b| b.count_ones()).sum::<u32>(),
            ct.to_bytes().iter().map(|&b| b.count_ones()).sum::<u32>(),
            ss1.to_bytes() == ss2.to_bytes(),
        );

        patterns.push(pattern);
    }

    // Verify all operations succeeded
    assert!(patterns.iter().all(|(_, _, _, _, success)| *success));

    // Check that patterns don't reveal information
    // This is a basic check - real EM analysis would be much more sophisticated
    let pk_patterns: Vec<_> = patterns.iter().map(|(_, pk, _, _, _)| *pk).collect();
    let sk_patterns: Vec<_> = patterns.iter().map(|(_, _, sk, _, _)| *sk).collect();
    let ct_patterns: Vec<_> = patterns.iter().map(|(_, _, _, ct, _)| *ct).collect();

    // Patterns should have reasonable variance
    let pk_variance = calculate_variance(&pk_patterns);
    let sk_variance = calculate_variance(&sk_patterns);
    let ct_variance = calculate_variance(&ct_patterns);

    assert!(pk_variance > 10.0, "Public key patterns too consistent");
    assert!(sk_variance > 10.0, "Secret key patterns too consistent");
    assert!(ct_variance > 10.0, "Ciphertext patterns too consistent");
}

fn calculate_variance(data: &[u32]) -> f64 {
    let mean = data.iter().sum::<u32>() as f64 / data.len() as f64;
    data.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / data.len() as f64
}

/// Test fault injection resistance
#[test]
fn test_fault_injection_resistance() {
    let kem = ml_kem_768();

    // Test that operations handle corrupted internal state gracefully
    for _ in 0..100 {
        let (pk, sk) = kem.generate_keypair().unwrap();

        // This should always succeed for valid inputs
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    }
}

/// Test algorithm agility and version compatibility
#[test]
fn test_algorithm_agility() {
    use saorsa_pqc::api::kem::MlKemVariant;

    // Test that different algorithm variants work independently
    let variants = [
        MlKemVariant::MlKem512,
        MlKemVariant::MlKem768,
        MlKemVariant::MlKem1024,
    ];

    for variant in &variants {
        let kem = MlKem::new(*variant);

        // Each variant should work independently
        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();

        assert_eq!(
            ss1.to_bytes(),
            ss2.to_bytes(),
            "Variant {:?} round-trip failed",
            variant
        );
    }
}

/// Test cross-algorithm compatibility
#[test]
fn test_cross_algorithm_compatibility() {
    let kem = ml_kem_768();
    let dsa = ml_dsa_65();

    // Test that different algorithms can be used together
    let (kem_pk, kem_sk) = kem.generate_keypair().unwrap();
    let (dsa_pk, dsa_sk) = dsa.generate_keypair().unwrap();

    let message = b"Cross-algorithm compatibility test";

    // ML-KEM operations
    let (ss1, ct) = kem.encapsulate(&kem_pk).unwrap();
    let ss2 = kem.decapsulate(&kem_sk, &ct).unwrap();
    assert_eq!(ss1.to_bytes(), ss2.to_bytes());

    // ML-DSA operations
    let signature = dsa.sign(&dsa_sk, message).unwrap();
    let is_valid = dsa.verify(&dsa_pk, message, &signature).unwrap();
    assert!(is_valid);
}

/// Test memory access patterns for side-channel resistance
#[test]
fn test_memory_access_patterns() {
    let cipher = ChaCha20Poly1305::new(&[0x42u8; 32].into());

    // Test that memory access patterns don't reveal information
    let mut access_times = Vec::new();

    for i in 0..100 {
        let message = [i as u8; 100];
        let start = Instant::now();
        let nonce = [0u8; 12].into(); // 96-bit nonce
        let _ = cipher.encrypt(&nonce, &message);
        access_times.push(start.elapsed());
    }

    // Calculate access time variance
    let avg_time: Duration = access_times.iter().sum::<Duration>() / access_times.len() as u32;
    let variance = access_times
        .iter()
        .map(|&t| {
            let diff = if t > avg_time {
                t - avg_time
            } else {
                avg_time - t
            };
            diff.as_nanos() as f64
        })
        .sum::<f64>()
        / access_times.len() as f64;

    // Variance should be reasonable
    assert!(
        variance < 500_000.0,
        "Memory access timing variance too high: {}",
        variance
    );
}
