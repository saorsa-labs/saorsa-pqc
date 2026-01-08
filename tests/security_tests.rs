//! Security test suite for saorsa-pqc
//!
//! Tests core security properties including constant-time operations

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

use saorsa_pqc::pqc::constant_time::ct_eq;
use std::time::{Duration, Instant};

/// Test that secret comparisons run in constant time
#[test]
fn test_constant_time_comparison() {
    // Skip detailed timing checks in CI with beta Rust and SIMD
    // These combinations can cause timing variations due to aggressive optimizations
    let is_ci = std::env::var("CI").is_ok();
    // Check if we're on beta channel by looking at rustc version
    let is_beta = std::env::var("RUSTUP_TOOLCHAIN")
        .map(|s| s.contains("beta"))
        .unwrap_or(false);
    let has_simd = cfg!(feature = "simd");

    if is_ci && is_beta && has_simd {
        eprintln!("Note: Relaxed timing check for CI with beta Rust and SIMD features");
    }

    // Create test data
    let secret1 = vec![0xAAu8; 1000];
    let secret2 = vec![0xAAu8; 1000];
    let secret3 = vec![0xBBu8; 1000];

    // Warm up
    for _ in 0..100 {
        let _ = ct_eq(&secret1, &secret2);
        let _ = ct_eq(&secret1, &secret3);
    }

    // Measure equal comparison timing
    let mut equal_times = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        let _ = ct_eq(&secret1, &secret2);
        equal_times.push(start.elapsed());
    }

    // Measure unequal comparison timing
    let mut unequal_times = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        let _ = ct_eq(&secret1, &secret3);
        unequal_times.push(start.elapsed());
    }

    // Calculate average times
    let avg_equal = average_duration(&equal_times);
    let avg_unequal = average_duration(&unequal_times);

    // Adjust tolerance based on environment
    // CI environments, especially with beta Rust and SIMD, need more tolerance
    let tolerance = if is_ci && is_beta && has_simd {
        4.0 // 400% tolerance for beta+SIMD in CI
    } else if is_ci {
        2.5 // 250% tolerance for CI environments
    } else {
        2.0 // 200% tolerance for local testing
    };

    let max_time = avg_equal.max(avg_unequal);
    let min_time = avg_equal.min(avg_unequal);

    if min_time.as_nanos() > 0 {
        let ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

        // Log timing information for debugging
        println!("Constant-time comparison timing:");
        println!("  Equal times: {:?}", avg_equal);
        println!("  Unequal times: {:?}", avg_unequal);
        println!(
            "  Ratio: {:.2}x (tolerance: {:.1}x)",
            ratio,
            1.0 + tolerance
        );

        assert!(
            ratio < 1.0 + tolerance,
            "Timing variation too large: {:.2}x difference (equal: {:?}, unequal: {:?})",
            ratio,
            avg_equal,
            avg_unequal
        );
    }

    println!("✅ Constant-time comparison test passed");
}

fn average_duration(durations: &[Duration]) -> Duration {
    let sum: Duration = durations.iter().sum();
    sum / durations.len() as u32
}

/// Test constant-time array equality
#[test]
fn test_constant_time_array_equality() {
    use saorsa_pqc::pqc::constant_time::ct_array_eq;

    let array1 = [0xAAu8; 32];
    let array2 = [0xAAu8; 32];
    let array3 = [0xBBu8; 32];

    // Test equal arrays
    assert!(ct_array_eq(&array1, &array2));

    // Test unequal arrays
    assert!(!ct_array_eq(&array1, &array3));

    println!("✅ Constant-time array equality test passed");
}

/// Test constant-time conditional selection
#[test]
fn test_constant_time_selection() {
    use saorsa_pqc::pqc::constant_time::ct_select;

    let a = 42u32;
    let b = 100u32;

    // Test selection with true condition
    assert_eq!(ct_select(&a, &b, true), a);

    // Test selection with false condition
    assert_eq!(ct_select(&a, &b, false), b);

    println!("✅ Constant-time selection test passed");
}

/// Test constant-time copy operation
#[test]
fn test_constant_time_copy() {
    use saorsa_pqc::pqc::constant_time::ct_copy_bytes;

    let src = [1u8, 2, 3, 4];
    let mut dest1 = [0u8; 4];
    let mut dest2 = [0u8; 4];

    // Copy with true condition
    let success1 = ct_copy_bytes(&mut dest1, &src, true);
    assert!(success1, "Copy with matching lengths should succeed");
    assert_eq!(dest1, src);

    // Copy with false condition (no-op but still succeeds because lengths match)
    let success2 = ct_copy_bytes(&mut dest2, &src, false);
    assert!(success2, "Copy with matching lengths should succeed even with choice=false");
    assert_eq!(dest2, [0, 0, 0, 0]);

    // Test mismatched lengths - should return false in constant time
    let mut dest3 = [0u8; 3]; // Different length
    let success3 = ct_copy_bytes(&mut dest3, &src, true);
    assert!(!success3, "Copy with mismatched lengths should return false");
    assert_eq!(dest3, [0, 0, 0], "Dest should be unchanged on length mismatch");

    println!("✅ Constant-time copy test passed");
}

/// Test constant-time secret option
#[test]
fn test_constant_time_secret_option() {
    use saorsa_pqc::pqc::constant_time::CtSecretOption;

    let some_val = CtSecretOption::some(42u32);
    let none_val = CtSecretOption::none(0u32);

    // Test is_some/is_none
    assert_eq!(some_val.is_some().unwrap_u8(), 1);
    assert_eq!(none_val.is_none().unwrap_u8(), 1);

    // Test unwrap_or
    assert_eq!(some_val.unwrap_or(100), 42);
    assert_eq!(none_val.unwrap_or(100), 100);

    println!("✅ Constant-time secret option test passed");
}

/// Test memory clearing functionality
#[test]
fn test_memory_clearing() {
    use saorsa_pqc::pqc::constant_time::ct_clear;

    let mut sensitive_data = vec![0xAAu8; 100];

    // Verify data is not all zeros initially
    assert!(!sensitive_data.iter().all(|&b| b == 0));

    // Clear the data
    ct_clear(&mut sensitive_data);

    // Verify data is now all zeros
    assert!(sensitive_data.iter().all(|&b| b == 0));

    println!("✅ Memory clearing test passed");
}

/// Performance test for constant-time operations overhead
#[test]
#[ignore] // Run with --ignored to include benchmarks
fn bench_constant_time_overhead() {
    let data1 = vec![0xAAu8; 10000];
    let data2 = vec![0xAAu8; 10000];
    let data3 = vec![0xBBu8; 10000];

    // Warm up
    for _ in 0..1000 {
        let _ = ct_eq(&data1, &data2);
        let _ = data1 == data2;
    }

    // Measure constant-time comparison
    let start = Instant::now();
    for _ in 0..10000 {
        let _ = ct_eq(&data1, &data2);
        let _ = ct_eq(&data1, &data3);
    }
    let ct_duration = start.elapsed();

    // Measure regular comparison
    let start = Instant::now();
    for _ in 0..10000 {
        let _ = data1 == data2;
        let _ = data1 == data3;
    }
    let regular_duration = start.elapsed();

    let overhead = if regular_duration.as_nanos() > 0 {
        (ct_duration.as_nanos() as f64 / regular_duration.as_nanos() as f64) - 1.0
    } else {
        0.0
    };

    println!(
        "Constant-time comparison overhead: {:.1}%",
        overhead * 100.0
    );
    println!("  Regular: {:?}", regular_duration);
    println!("  Constant-time: {:?}", ct_duration);

    // Overhead should be reasonable (less than 50x for worst case)
    assert!(
        overhead < 49.0,
        "Constant-time overhead too high: {:.1}x",
        overhead + 1.0
    );

    println!("✅ Performance benchmark passed");
}

/// Test that constant-time operations work correctly under load
#[test]
fn test_constant_time_under_load() {
    use std::sync::Arc;
    use std::thread;

    let data1 = Arc::new(vec![0xAAu8; 1000]);
    let data2 = Arc::new(vec![0xAAu8; 1000]);
    let data3 = Arc::new(vec![0xBBu8; 1000]);

    let mut handles = vec![];

    // Spawn multiple threads doing constant-time operations
    for i in 0..4 {
        let d1 = Arc::clone(&data1);
        let d2 = Arc::clone(&data2);
        let d3 = Arc::clone(&data3);

        let handle = thread::spawn(move || {
            for _ in 0..1000 {
                let equal = ct_eq(&d1, &d2);
                let unequal = ct_eq(&d1, &d3);
                assert!(equal, "Thread {} failed equal comparison", i);
                assert!(!unequal, "Thread {} failed unequal comparison", i);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    println!("✅ Constant-time under load test passed");
}

/// Test various edge cases for constant-time operations
#[test]
fn test_constant_time_edge_cases() {
    // Test with empty slices
    assert!(ct_eq(&[], &[]));
    assert!(!ct_eq(&[1], &[]));
    assert!(!ct_eq(&[], &[1]));

    // Test with different lengths
    assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    assert!(!ct_eq(&[1, 2, 3], &[1, 2]));

    // Test with single bytes
    assert!(ct_eq(&[42], &[42]));
    assert!(!ct_eq(&[42], &[43]));

    // Test with large identical data
    let large1 = vec![0x55u8; 100000];
    let large2 = vec![0x55u8; 100000];
    assert!(ct_eq(&large1, &large2));

    // Test with large different data (different at end)
    let mut large3 = vec![0x55u8; 100000];
    large3[99999] = 0x56;
    assert!(!ct_eq(&large1, &large3));

    println!("✅ Constant-time edge cases test passed");
}
