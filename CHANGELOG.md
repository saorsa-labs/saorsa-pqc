# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-01-08

### Added
- **DudeCT Constant-Time Verification**: Formal statistical testing for timing attack resistance
  - 8 comprehensive benchmarks covering all constant-time primitives
  - CI workflow (`ct-verification.yml`) with automated verification on every PR
  - Extended analysis mode for thorough weekly verification
- **Enhanced Constant-Time Copy**: `ct_copy_bytes` now handles length mismatches securely
  - Returns `bool` indicating whether lengths matched (constant-time)
  - Processes maximum length with dummy operations to prevent timing leaks
  - Added `#[must_use]` attribute to enforce result checking

### Changed
- **BREAKING**: `ct_copy_bytes` signature changed from `fn(...) -> ()` to `fn(...) -> bool`
  - Old code that ignored the return value will receive compiler warnings
  - Behavior change: previously silently failed on length mismatch (timing leak); now returns `false` in constant time
- **AAD Hash Comparison**: Replaced non-constant-time `!=` with `ct_eq()` in encryption module
  - Prevents timing oracle attacks on authentication tag verification

### Security
- **Side-Channel Protection Rating**: Upgraded from "Good" to "Excellent"
- **Timing Leak Fixes**: Two critical timing vulnerabilities patched
  - `ct_copy_bytes` early-exit on length mismatch
  - AAD hash comparison using standard equality
- **Formal Verification**: DudeCT statistical analysis confirms `max_t < 5` (constant-time)

### Technical Details
- DudeCT benchmarks test: `ct_eq`, `ct_array_eq`, `ct_copy_bytes`, `ct_select`
- Test scenarios: equal vs different data, early vs late differences, random data, empty slices
- CI threshold: `|max_t| < 4.5` (below 5.0 which indicates timing leak)

### Migration Guide
```rust
// Before (0.3.x)
ct_copy_bytes(&mut dest, &src, true);  // Silently failed if lengths differed

// After (0.4.0)
let success = ct_copy_bytes(&mut dest, &src, true);
if !success {
    // Handle length mismatch
}
// Or use assert for same-length guarantees:
assert!(ct_copy_bytes(&mut dest, &src, true), "Length mismatch");
```

## [0.3.12] - 2025-01-20

### Added
- **HKDF public API exposure** - Exported HKDF types and helper functions in the public API
- **Comprehensive HKDF tests** - Added 11 integration tests covering all HKDF functionality
- **HKDF usage examples** - Created detailed example demonstrating various HKDF use cases including ML-KEM integration

### Changed
- **Updated HKDF dependency** - Upgraded from version 0.12 to 0.12.4 for latest improvements
- **Enhanced KDF exports** - Added `HkdfSha3_256`, `HkdfSha3_512`, `KdfAlgorithm`, and `kdf_helpers` to public exports

### Fixed
- **Removed invalid cargo-mutants dependency** - Eliminated compilation warning by removing binary-only dependency

### Technical Details
- HKDF implementation uses SHA3 variants for quantum resistance
- Includes helper functions for common patterns: key hierarchies, password derivation, and enc/auth key pairs
- Full integration with existing ML-KEM for post-quantum key derivation

## [0.3.3] - 2025-01-18

### Added
- **Comprehensive cryptographic trait system** - Standardized interfaces for KEM, signatures, hash, KDF, AEAD, and MAC operations
- **Hash module** (`api/hash.rs`) - BLAKE3, SHA3-256, SHA3-512, and SHAKE256 implementations
- **KDF module** (`api/kdf.rs`) - HKDF-SHA3-256 and HKDF-SHA3-512 for key derivation
- **HMAC module** (`api/hmac.rs`) - HMAC-SHA3-256 and HMAC-SHA3-512 with constant-time verification
- **AEAD module** (`api/aead.rs`) - AES-256-GCM support alongside existing ChaCha20-Poly1305
- **HPKE module** (`api/hpke.rs`) - Hybrid Public Key Encryption bound to ML-KEM variants (RFC 9180)
- Feature flags for optional cryptographic functionality (`hpke-support`, `extended-crypto`)

### Changed
- **BREAKING**: Renamed `api/dsa.rs` to `api/sig.rs` for consistency with signature terminology
- All imports from `api::dsa` must now use `api::sig`
- Enhanced error types with new variants for cryptographic operations

### Fixed
- Test imports updated to use new `api::sig` module path
- Type annotation issues in AEAD implementations
- HMAC trait disambiguation for `new_from_slice` methods

### Technical Details
- All new modules use existing high-quality cryptographic crates (no custom implementations)
- Zero-copy where possible with proper zeroization of sensitive data
- Comprehensive test coverage for all new modules
- Maintains backward compatibility except for the DSA→SIG rename

## [0.3.2] - 2025-01-17

### Added
- ChaCha20-Poly1305 as the primary quantum-secure symmetric encryption
- Comprehensive documentation highlighting quantum resistance
- Clear guidance on 256-bit key requirements for quantum security

### Changed
- Made ChaCha20-Poly1305 the prominent symmetric encryption choice
- Updated all examples to use ChaCha20-Poly1305
- Enhanced API documentation with security recommendations

### Fixed
- All test failures resolved - 100% test pass rate
- Compilation warnings eliminated

## [0.3.1] - 2025-01-16

### Added
- Initial release with ML-KEM and ML-DSA support
- SLH-DSA implementation
- Basic symmetric encryption support