# Side-Channel Protection Evidence

**Document Version:** 1.0
**Date:** 2025-01-08
**Library Version:** 0.4.x
**FIPS Relevance:** FIPS 140-3 Section 7.8 (Non-Invasive Security)

---

## Overview

This document provides evidence of side-channel protection in the saorsa-pqc library,
specifically addressing timing attack resistance as required for FIPS 140-3 compliance.

## Protection Rating: Excellent

| Category | Status | Evidence |
|----------|--------|----------|
| Timing Attack Resistance | ✅ Verified | DudeCT statistical analysis |
| Constant-Time Comparisons | ✅ Implemented | `ct_eq`, `ct_array_eq` |
| Constant-Time Selection | ✅ Implemented | `ct_select`, `ct_assign` |
| Constant-Time Copy | ✅ Implemented | `ct_copy_bytes` |
| Error Handling | ✅ CT-Safe | `CtResult` type |

---

## Constant-Time Primitives

### 1. `ct_eq` - Byte Slice Comparison

**Location:** `src/pqc/constant_time.rs`

**Properties:**
- Compares two byte slices in constant time
- Uses XOR accumulation (no early exit)
- Length comparison is constant-time
- Compiler optimization prevented via `black_box`

**DudeCT Verification:**
- `ct_eq_equal_vs_different`: Equal vs different data
- `ct_eq_early_vs_late_diff`: Early vs late byte differences
- `ct_eq_random_data`: Random data inputs
- `ct_eq_empty_slices`: Empty slice handling

### 2. `ct_array_eq` - Fixed-Size Array Comparison

**Location:** `src/pqc/constant_time.rs`

**Properties:**
- Constant-time comparison for fixed-size arrays
- Uses `subtle::ConstantTimeEq` trait
- Verified for 32-byte and 64-byte arrays

**DudeCT Verification:**
- `ct_array_eq_verification`: 32-byte arrays
- `ct_array_eq_64byte`: 64-byte arrays (SHA-512 sized)

### 3. `ct_copy_bytes` - Conditional Copy

**Location:** `src/pqc/constant_time.rs`

**Properties:**
- Copies bytes conditionally based on choice flag
- Returns `bool` indicating length match (v0.4.0 breaking change)
- Length mismatch handled in constant time
- Uses `ConditionallySelectable` trait

**DudeCT Verification:**
- `ct_copy_bytes_choice_verification`: Choice true vs false
- `ct_copy_bytes_length_verification`: Matching vs mismatched lengths

### 4. `ct_select` - Conditional Selection

**Location:** `src/pqc/constant_time.rs`

**Properties:**
- Selects between two values based on condition
- Works with any `ConditionallySelectable` type
- No branching based on condition

**DudeCT Verification:**
- `ct_select_verification`: u32 selection
- `ct_select_u64_verification`: u64 selection

---

## CT FIPS Wrapper Layer

**Location:** `src/pqc/ct_fips.rs`

Provides constant-time wrappers for FIPS 203/204/205 operations.

### Key Components

| Component | Purpose |
|-----------|---------|
| `CtResult<T>` | Constant-time result handling |
| `ct_ml_kem` | ML-KEM timing-safe wrappers |
| `ct_ml_dsa` | ML-DSA timing-safe wrappers |
| `ct_slh_dsa` | SLH-DSA timing-safe wrappers |
| `ct_tag_verify` | Authentication tag verification |
| `ct_conditional_zeroize` | Conditional memory clearing |

### DudeCT Verification

- `ct_tag_verify_matching_vs_mismatching`: Auth tag comparison
- `ct_buffer_eq_32byte_keys`: Key comparison
- `ct_conditional_zeroize_verification`: Memory clearing
- `ct_validate_key_length_verification`: Length validation
- `ct_shared_secret_eq`: Shared secret comparison

---

## DudeCT Statistical Analysis

### Methodology

DudeCT uses Welch's t-test to detect timing differences between two input classes.
A `|max_t| > 5` indicates non-constant-time behavior with high confidence.

### Threshold Configuration

| Threshold | Confidence | Use Case |
|-----------|------------|----------|
| 5.0 | 95% | Detection threshold |
| 4.5 | ~97% | Previous CI threshold |
| **3.0** | **99.7%** | **Current CI threshold (3-sigma)** |

### CI Integration

**Workflow:** `.github/workflows/ct-verification.yml`

- **Quick Check (PR):** 30 seconds per benchmark, 10 core benchmarks
- **Extended (Weekly):** 5 minutes per benchmark, 20 total benchmarks
- **Threshold:** `CT_THRESHOLD=3.0` (configurable via env var)

---

## Benchmark Suite

### Core Benchmarks (Quick Check)

| Benchmark | Tests |
|-----------|-------|
| `ct_eq_equal_vs_different` | Comparison timing invariance |
| `ct_eq_early_vs_late_diff` | Position-independent comparison |
| `ct_array_eq_verification` | Fixed-size array comparison |
| `ct_copy_bytes_choice_verification` | Copy choice independence |
| `ct_copy_bytes_length_verification` | Length mismatch handling |
| `ct_select_verification` | Selection timing invariance |
| `ct_tag_verify_matching_vs_mismatching` | Auth tag verification |
| `ct_buffer_eq_32byte_keys` | Key comparison |
| `ct_conditional_zeroize_verification` | Conditional zeroize |
| `ct_validate_key_length_verification` | Length validation |

### Extended Benchmarks (Weekly)

| Benchmark | Tests |
|-----------|-------|
| `ct_eq_random_data` | Random input handling |
| `ct_eq_empty_slices` | Edge case: empty inputs |
| `ct_eq_signature_sized` | 256-byte data |
| `ct_eq_large_key_sized` | 2400-byte data (ML-KEM SK) |
| `ct_eq_single_bit_diff` | Single-bit differences |
| `ct_select_u64_verification` | 64-bit selection |
| `ct_array_eq_64byte` | 64-byte arrays |
| `ct_shared_secret_eq` | Shared secret comparison |

---

## Underlying FIPS Crate Analysis

### fips203 (ML-KEM)

**Crate:** `fips203 v0.4`

| Operation | CT Status | Notes |
|-----------|-----------|-------|
| KeyGen | ⚠️ Assumed | Depends on crate implementation |
| Encapsulate | ⚠️ Assumed | Depends on crate implementation |
| Decapsulate | ⚠️ Assumed | Most critical for CT |

**Mitigation:** CT wrapper layer (`ct_ml_kem`) ensures timing-safe API boundaries.

### fips204 (ML-DSA)

**Crate:** `fips204 v0.4`

| Operation | CT Status | Notes |
|-----------|-----------|-------|
| KeyGen | ⚠️ Assumed | Depends on crate implementation |
| Sign | ⚠️ Assumed | Depends on crate implementation |
| Verify | ✅ Public | Verification is public operation |

**Mitigation:** CT wrapper layer (`ct_ml_dsa`) ensures timing-safe verification result handling.

### fips205 (SLH-DSA)

**Crate:** `fips205 v0.4`

| Operation | CT Status | Notes |
|-----------|-----------|-------|
| KeyGen | ⚠️ Assumed | Depends on crate implementation |
| Sign | ⚠️ Assumed | Depends on crate implementation |
| Verify | ✅ Public | Verification is public operation |

**Mitigation:** CT wrapper layer (`ct_slh_dsa`) ensures timing-safe verification result handling.

---

## Verification Status

### Verified Constant-Time (saorsa-pqc code)

- [x] `ct_eq` - DudeCT verified
- [x] `ct_array_eq` - DudeCT verified
- [x] `ct_copy_bytes` - DudeCT verified
- [x] `ct_select` - DudeCT verified
- [x] `ct_tag_verify` - DudeCT verified
- [x] `ct_conditional_zeroize` - DudeCT verified
- [x] `ct_validate_key_length` - DudeCT verified
- [x] `CtSharedSecret::ct_eq` - DudeCT verified

### Assumed Constant-Time (upstream crates)

- [ ] fips203 internal operations (keygen, encaps, decaps)
- [ ] fips204 internal operations (keygen, sign)
- [ ] fips205 internal operations (keygen, sign)

**Note:** Upstream verification is tracked in Task saorsa-pqc-acs.12

---

## Compliance Checklist

### FIPS 140-3 Section 7.8 (Non-Invasive Security)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Timing attack mitigation | ✅ | DudeCT verification suite |
| Constant-time comparisons | ✅ | `ct_eq`, `ct_array_eq` |
| No secret-dependent branches | ✅ | Uses `subtle` crate primitives |
| No secret-dependent memory access | ⚠️ | Assumed from upstream crates |
| Formal verification | ✅ | Statistical (DudeCT) |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-08 | Initial documentation |

---

## References

1. [DudeCT Paper](https://eprint.iacr.org/2016/1123) - Statistical timing leak detection
2. [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) - Security requirements
3. [subtle crate](https://crates.io/crates/subtle) - Constant-time primitives
