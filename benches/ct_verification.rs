//! DudeCT constant-time verification benchmarks
//!
//! This benchmark suite uses statistical timing analysis to verify that
//! cryptographic operations execute in constant time regardless of input values.
//!
//! Run with: cargo bench --bench ct_verification
//!
//! The test compares timing distributions between two input classes (Left/Right).
//! A max_t value > 5 suggests non-constant-time behavior.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::RngCore;
use saorsa_pqc::pqc::constant_time::{ct_array_eq, ct_copy_bytes, ct_eq, ct_select};

/// Verify ct_eq is constant-time regardless of whether data matches
///
/// Left: Compare identical data (all 0xAA)
/// Right: Compare different data (0xAA vs 0xBB)
///
/// Both should take the same time if constant-time.
fn ct_eq_equal_vs_different(runner: &mut CtRunner, rng: &mut BenchRng) {
    let size = 1000;

    // Create test data
    let data_a = vec![0xAAu8; size];
    let data_b_same = vec![0xAAu8; size];
    let data_b_diff = vec![0xBBu8; size];

    // Randomly choose which class to measure
    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    // Run the operation
    runner.run_one(class, || {
        let result = match class {
            Class::Left => ct_eq(&data_a, &data_b_same),   // Equal comparison
            Class::Right => ct_eq(&data_a, &data_b_diff), // Unequal comparison
        };
        std::hint::black_box(result)
    });
}

/// Verify ct_eq handles early vs late differences uniformly
///
/// Left: Difference at first byte
/// Right: Difference at last byte
///
/// Non-constant-time code often early-exits on first difference.
fn ct_eq_early_vs_late_diff(runner: &mut CtRunner, rng: &mut BenchRng) {
    let size = 1000;

    // Create test data with difference at start
    let mut data_early_diff = vec![0xAAu8; size];
    data_early_diff[0] = 0xBB;

    // Create test data with difference at end
    let mut data_late_diff = vec![0xAAu8; size];
    data_late_diff[size - 1] = 0xBB;

    let reference = vec![0xAAu8; size];

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        let result = match class {
            Class::Left => ct_eq(&reference, &data_early_diff),
            Class::Right => ct_eq(&reference, &data_late_diff),
        };
        std::hint::black_box(result)
    });
}

/// Verify ct_array_eq is constant-time for fixed-size arrays
///
/// Left: Equal 32-byte arrays
/// Right: Different 32-byte arrays
fn ct_array_eq_verification(runner: &mut CtRunner, rng: &mut BenchRng) {
    let array_a = [0xAAu8; 32];
    let array_b_same = [0xAAu8; 32];
    let array_b_diff = [0xBBu8; 32];

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        let result = match class {
            Class::Left => ct_array_eq(&array_a, &array_b_same),
            Class::Right => ct_array_eq(&array_a, &array_b_diff),
        };
        std::hint::black_box(result)
    });
}

/// Verify ct_copy_bytes is constant-time regardless of copy condition
///
/// Left: Copy with choice=true
/// Right: Copy with choice=false (no-op but should take same time)
fn ct_copy_bytes_choice_verification(runner: &mut CtRunner, rng: &mut BenchRng) {
    let src = [0xAAu8; 64];

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        // Create buffers inside closure to avoid mutable borrow issues
        let mut dest = [0u8; 64];
        let choice = matches!(class, Class::Left);
        let result = ct_copy_bytes(&mut dest, &src, choice);
        std::hint::black_box(result)
    });
}

/// Verify ct_copy_bytes handles length mismatches in constant time
///
/// Left: Matching lengths
/// Right: Mismatched lengths (should still be constant-time)
fn ct_copy_bytes_length_verification(runner: &mut CtRunner, rng: &mut BenchRng) {
    let src_match = [0xAAu8; 64];
    let src_short = [0xAAu8; 32];

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        // Create buffer inside closure to avoid mutable borrow issues
        let mut dest = [0u8; 64];
        let result = match class {
            Class::Left => ct_copy_bytes(&mut dest, &src_match, true),
            Class::Right => ct_copy_bytes(&mut dest, &src_short, true),
        };
        std::hint::black_box(result)
    });
}

/// Verify ct_select is constant-time regardless of selection
///
/// Left: Select a (choice=true)
/// Right: Select b (choice=false)
fn ct_select_verification(runner: &mut CtRunner, rng: &mut BenchRng) {
    let a = 42u32;
    let b = 100u32;

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        let result = match class {
            Class::Left => ct_select(&a, &b, true),
            Class::Right => ct_select(&a, &b, false),
        };
        std::hint::black_box(result)
    });
}

/// Verify ct_eq with random data maintains constant-time properties
///
/// Uses fresh random data each iteration to test across input space.
fn ct_eq_random_data(runner: &mut CtRunner, rng: &mut BenchRng) {
    let size = 256;
    let mut data_a = vec![0u8; size];
    let mut data_b = vec![0u8; size];
    let mut data_c = vec![0u8; size];

    rng.fill_bytes(&mut data_a);
    data_b.copy_from_slice(&data_a); // Same as data_a
    rng.fill_bytes(&mut data_c); // Different random data

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        let result = match class {
            Class::Left => ct_eq(&data_a, &data_b),  // Equal
            Class::Right => ct_eq(&data_a, &data_c), // Likely different
        };
        std::hint::black_box(result)
    });
}

/// Verify ct_eq handles empty slices in constant time
fn ct_eq_empty_slices(runner: &mut CtRunner, rng: &mut BenchRng) {
    let empty: &[u8] = &[];
    let non_empty = [0xAAu8; 32];

    let class = if rng.next_u32() % 2 == 0 {
        Class::Left
    } else {
        Class::Right
    };

    runner.run_one(class, || {
        let result = match class {
            Class::Left => ct_eq(empty, empty),          // Empty vs empty
            Class::Right => ct_eq(empty, &non_empty[..0]), // Empty vs empty slice
        };
        std::hint::black_box(result)
    });
}

// Register all benchmarks with the dudect framework
ctbench_main!(
    ct_eq_equal_vs_different,
    ct_eq_early_vs_late_diff,
    ct_array_eq_verification,
    ct_copy_bytes_choice_verification,
    ct_copy_bytes_length_verification,
    ct_select_verification,
    ct_eq_random_data,
    ct_eq_empty_slices
);
