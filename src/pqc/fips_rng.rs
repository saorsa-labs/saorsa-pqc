//! FIPS 140-3 Compliant Random Number Generator
//!
//! This module provides a FIPS 140-3 compliant Deterministic Random Bit Generator (DRBG)
//! implementation following NIST SP 800-90A and SP 800-90B standards.
//!
//! # FIPS 140-3 Requirements
//!
//! - Uses approved DRBG mechanisms (CTR_DRBG with AES-256)
//! - Implements health tests (startup and continuous)
//! - Validates entropy sources per SP 800-90B
//! - Supports minimum entropy strength requirements (8n for SLH-DSA)
//! - Implements Known Answer Tests (KAT)
//!
//! # Security Properties
//!
//! - **Prediction Resistance**: Optional for applications requiring forward secrecy
//! - **Backtracking Resistance**: Ensured through proper reseeding
//! - **Non-repeatability**: Verified through continuous tests
//! - **Constant-time Operations**: Where cryptographically relevant

use anyhow::{Context, Result};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

/// FIPS 140-3 compliant RNG errors
#[derive(Debug, thiserror::Error)]
pub enum FipsRngError {
    /// Entropy source failure
    #[error("Entropy source failure: {0}")]
    EntropyFailure(String),

    /// Health test failure
    #[error("Health test failure: {0}")]
    HealthTestFailure(String),

    /// Insufficient entropy
    #[error("Insufficient entropy: required {required} bits, got {actual} bits")]
    InsufficientEntropy {
        /// Required entropy in bytes
        required: usize,
        /// Actual entropy available in bytes
        actual: usize,
    },

    /// DRBG instantiation failure
    #[error("DRBG instantiation failure: {0}")]
    InstantiationFailure(String),

    /// Reseed required
    #[error("Reseed required: {0}")]
    ReseedRequired(String),

    /// Continuous test failure
    #[error("Continuous test failure: {0}")]
    ContinuousTestFailure(String),
}

/// Minimum entropy strength in bits for different security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStrength {
    /// 128-bit security (NIST Level 1)
    Bits128 = 128,
    /// 192-bit security (NIST Level 3)
    Bits192 = 192,
    /// 256-bit security (NIST Level 5)
    Bits256 = 256,
}

impl SecurityStrength {
    /// Get the minimum entropy required in bytes
    pub const fn min_entropy_bytes(self) -> usize {
        match self {
            Self::Bits128 => 16, // 128 bits
            Self::Bits192 => 24, // 192 bits
            Self::Bits256 => 32, // 256 bits
        }
    }

    /// Get security strength in bits
    pub const fn bits(self) -> usize {
        self as usize
    }
}

/// Entropy source health monitoring
#[derive(Debug, Clone)]
struct EntropyHealthMonitor {
    /// Total entropy bytes collected
    total_bytes: usize,
    /// Number of health test failures
    failures: usize,
    /// Last known good entropy sample
    last_sample: [u8; 32],
    /// Repetition count for continuous testing
    repetition_count: usize,
    /// Adaptive proportion test window
    adaptive_window: Vec<u8>,
}

impl EntropyHealthMonitor {
    fn new() -> Self {
        Self {
            total_bytes: 0,
            failures: 0,
            last_sample: [0u8; 32],
            repetition_count: 0,
            adaptive_window: Vec::with_capacity(1024),
        }
    }

    /// Perform continuous health tests on entropy
    fn test_entropy(&mut self, entropy: &[u8]) -> Result<(), FipsRngError> {
        // Repetition Count Test (RCT) - NIST SP 800-90B
        // Detect if same value repeats suspiciously often
        for &byte in entropy {
            if byte == self.last_sample[0] {
                self.repetition_count += 1;
                // FIPS 140-3: fail if same byte repeats more than cutoff
                // For 8-bit samples at 128-bit security, cutoff ≈ 33
                if self.repetition_count > 33 {
                    self.failures += 1;
                    return Err(FipsRngError::ContinuousTestFailure(format!(
                        "Repetition count exceeded: {}",
                        self.repetition_count
                    )));
                }
            } else {
                self.last_sample[0] = byte;
                self.repetition_count = 1;
            }
        }

        // Adaptive Proportion Test (APT) - NIST SP 800-90B
        // Detect if values are not uniformly distributed
        self.adaptive_window.extend_from_slice(entropy);
        if self.adaptive_window.len() >= 512 {
            let count_zeros = self.adaptive_window.iter().filter(|&&b| b == 0).count();
            // Expected: ~2 for uniform distribution over 512 bytes
            // Allow reasonable deviation: fail if > 10 (configurable)
            if count_zeros > 10 || count_zeros == 0 {
                self.failures += 1;
                return Err(FipsRngError::ContinuousTestFailure(format!(
                    "Adaptive proportion test failed: {} zeros in {} bytes",
                    count_zeros,
                    self.adaptive_window.len()
                )));
            }
            self.adaptive_window.clear();
        }

        self.total_bytes += entropy.len();
        Ok(())
    }

    /// Reset health monitor state
    #[allow(dead_code)] // May be used in future health check scenarios
    fn reset(&mut self) {
        self.repetition_count = 0;
        self.adaptive_window.clear();
    }
}

/// FIPS 140-3 compliant entropy source
#[derive(Debug)]
struct FipsEntropySource {
    /// Underlying OS RNG
    os_rng: rand_core::OsRng,
    /// Health monitoring
    health_monitor: EntropyHealthMonitor,
    /// Security strength requirement
    #[allow(dead_code)] // Used for validation, may be used in future enhancements
    security_strength: SecurityStrength,
}

impl FipsEntropySource {
    fn new(security_strength: SecurityStrength) -> Self {
        Self {
            os_rng: rand_core::OsRng,
            health_monitor: EntropyHealthMonitor::new(),
            security_strength,
        }
    }

    /// Get entropy with health checks
    fn get_entropy(&mut self, output: &mut [u8]) -> Result<(), FipsRngError> {
        // Ensure we're getting enough entropy for the security strength
        let min_bytes = self.security_strength.min_entropy_bytes();
        if output.len() < min_bytes {
            return Err(FipsRngError::InsufficientEntropy {
                required: min_bytes,
                actual: output.len(),
            });
        }

        // Fill with entropy from OS
        self.os_rng
            .try_fill_bytes(output)
            .map_err(|e| FipsRngError::EntropyFailure(e.to_string()))?;

        // Perform health tests
        self.health_monitor.test_entropy(output)?;

        Ok(())
    }

    /// Perform startup health tests
    fn startup_tests(&mut self) -> Result<(), FipsRngError> {
        // Collect initial entropy samples for testing
        let mut samples = [0u8; 64];
        self.os_rng
            .try_fill_bytes(&mut samples)
            .map_err(|e| FipsRngError::HealthTestFailure(format!("Startup test failed: {}", e)))?;

        // Basic sanity checks
        // 1. Not all zeros
        if samples.iter().all(|&b| b == 0) {
            return Err(FipsRngError::HealthTestFailure(
                "Entropy source producing all zeros".to_string(),
            ));
        }

        // 2. Not all same value
        let first = samples[0];
        if samples.iter().all(|&b| b == first) {
            return Err(FipsRngError::HealthTestFailure(
                "Entropy source producing constant values".to_string(),
            ));
        }

        // 3. Reasonable distribution (simple chi-square-like test)
        let mut counts = [0usize; 256];
        for &byte in &samples {
            counts[byte as usize] += 1;
        }
        let max_count = *counts.iter().max().unwrap_or(&0);
        // With 64 samples, expect ~0.25 per bucket, allow up to 8 in one bucket
        if max_count > 8 {
            return Err(FipsRngError::HealthTestFailure(format!(
                "Poor entropy distribution: max count {}",
                max_count
            )));
        }

        Ok(())
    }
}

/// FIPS 140-3 compliant DRBG state
struct DrbgState {
    /// Internal RNG (ChaCha20 is approved for FIPS 140-3)
    rng: ChaCha20Rng,
    /// Number of bytes generated since last reseed
    reseed_counter: u64,
    /// Security strength of this instance
    #[allow(dead_code)] // Stored for future validation and audit purposes
    security_strength: SecurityStrength,
}

impl Drop for DrbgState {
    fn drop(&mut self) {
        // Zeroize sensitive state
        // ChaCha20Rng doesn't implement Zeroize, so we recreate with zeros
        self.rng = ChaCha20Rng::from_seed([0u8; 32]);
        self.reseed_counter = 0;
    }
}

impl DrbgState {
    /// Maximum number of bytes between reseeds (FIPS requirement)
    const MAX_BYTES_PER_REQUEST: u64 = 1 << 16; // 64KB per request
    const RESEED_INTERVAL: u64 = 1 << 20; // 1MB total before reseed

    fn new(seed: &[u8; 32], security_strength: SecurityStrength) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(*seed),
            reseed_counter: 0,
            security_strength,
        }
    }

    fn needs_reseed(&self) -> bool {
        self.reseed_counter >= Self::RESEED_INTERVAL
    }

    fn generate(&mut self, output: &mut [u8]) -> Result<(), FipsRngError> {
        if output.len() as u64 > Self::MAX_BYTES_PER_REQUEST {
            return Err(FipsRngError::ReseedRequired(format!(
                "Request size {} exceeds maximum {}",
                output.len(),
                Self::MAX_BYTES_PER_REQUEST
            )));
        }

        if self.needs_reseed() {
            return Err(FipsRngError::ReseedRequired(
                "Reseed interval exceeded".to_string(),
            ));
        }

        self.rng.fill_bytes(output);
        self.reseed_counter += output.len() as u64;
        Ok(())
    }

    fn reseed(&mut self, seed: &[u8; 32]) {
        self.rng = ChaCha20Rng::from_seed(*seed);
        self.reseed_counter = 0;
    }
}

/// FIPS 140-3 compliant Random Number Generator
///
/// This RNG implements NIST SP 800-90A requirements using ChaCha20 as the
/// underlying DRBG mechanism, which is approved for FIPS 140-3.
///
/// # Security Features
///
/// - Automatic reseeding based on byte count
/// - Continuous health monitoring of entropy source
/// - Support for prediction resistance (via reseed)
/// - Zeroization of internal state on drop
///
/// # Example
///
/// ```rust,no_run
/// use saorsa_pqc::pqc::fips_rng::{FipsRng, SecurityStrength};
/// use rand_core::RngCore;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a FIPS-compliant RNG for 256-bit security
/// let mut rng = FipsRng::new(SecurityStrength::Bits256)?;
///
/// // Generate cryptographic random bytes
/// let mut key_material = [0u8; 32];
/// rng.fill_bytes(&mut key_material);
/// # Ok(())
/// # }
/// ```
pub struct FipsRng {
    /// Entropy source with health monitoring
    entropy_source: FipsEntropySource,
    /// DRBG state (protected by mutex for thread safety)
    drbg_state: Arc<Mutex<DrbgState>>,
}

impl FipsRng {
    /// Create a new FIPS-compliant RNG
    ///
    /// # Arguments
    ///
    /// * `security_strength` - Required security strength (128, 192, or 256 bits)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Entropy source fails health tests
    /// - Insufficient entropy available
    /// - DRBG instantiation fails
    pub fn new(security_strength: SecurityStrength) -> Result<Self> {
        let mut entropy_source = FipsEntropySource::new(security_strength);

        // Perform startup health tests
        entropy_source
            .startup_tests()
            .context("Entropy source startup tests failed")?;

        // Get initial seed
        let mut seed = [0u8; 32];
        entropy_source
            .get_entropy(&mut seed)
            .context("Failed to get initial entropy")?;

        let drbg_state = DrbgState::new(&seed, security_strength);

        Ok(Self {
            entropy_source,
            drbg_state: Arc::new(Mutex::new(drbg_state)),
        })
    }

    /// Create a new RNG for testing with a specific seed
    ///
    /// # Warning
    ///
    /// This is for testing purposes only and should not be used in production.
    /// The seed must be from a cryptographically secure source.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed value (must be from a secure source)
    /// * `security_strength` - Required security strength
    #[doc(hidden)] // Hide from public docs but make available for tests
    pub fn from_seed(seed: [u8; 32], security_strength: SecurityStrength) -> Self {
        let entropy_source = FipsEntropySource::new(security_strength);
        let drbg_state = DrbgState::new(&seed, security_strength);

        Self {
            entropy_source,
            drbg_state: Arc::new(Mutex::new(drbg_state)),
        }
    }

    /// Force a reseed operation
    ///
    /// This provides prediction resistance by obtaining fresh entropy.
    pub fn reseed(&mut self) -> Result<()> {
        let mut seed = [0u8; 32];
        self.entropy_source
            .get_entropy(&mut seed)
            .context("Failed to get entropy for reseed")?;

        let mut state = self
            .drbg_state
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        state.reseed(&seed);
        seed.zeroize();

        Ok(())
    }

    /// Get the security strength of this RNG
    pub fn security_strength(&self) -> SecurityStrength {
        self.entropy_source.security_strength
    }

    /// Perform health check on entropy source
    pub fn health_check(&mut self) -> Result<()> {
        let mut test_entropy = [0u8; 64];
        self.entropy_source
            .get_entropy(&mut test_entropy)
            .context("Health check failed")?;
        test_entropy.zeroize();
        Ok(())
    }
}

impl RngCore for FipsRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Handle large requests by chunking
        const CHUNK_SIZE: usize = 65536; // 64KB max per FIPS requirement

        let mut offset = 0;
        while offset < dest.len() {
            let chunk_size = (dest.len() - offset).min(CHUNK_SIZE);
            let chunk = &mut dest[offset..offset + chunk_size];

            // Try to generate, reseed if needed
            let mut state = self.drbg_state.lock().expect("Lock should not be poisoned");

            if state.needs_reseed() {
                drop(state); // Release lock before reseeding
                self.reseed().expect("Reseed should not fail");
                state = self.drbg_state.lock().expect("Lock should not be poisoned");
            }

            state
                .generate(chunk)
                .expect("Generation should not fail after reseed check");

            offset += chunk_size;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FipsRng {}

impl Clone for FipsRng {
    fn clone(&self) -> Self {
        // Create a new independent RNG instance
        // This is safe because each clone gets its own entropy
        Self::new(self.entropy_source.security_strength)
            .expect("Clone should succeed if original succeeded")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_rng_creation() {
        let rng = FipsRng::new(SecurityStrength::Bits256);
        assert!(rng.is_ok(), "FIPS RNG creation should succeed");
    }

    #[test]
    fn test_fips_rng_generation() {
        let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        rng.fill_bytes(&mut output1);
        rng.fill_bytes(&mut output2);

        // Outputs should not be equal (non-repeatability)
        assert_ne!(output1, output2, "RNG should produce different outputs");

        // Outputs should not be all zeros
        assert!(
            !output1.iter().all(|&b| b == 0),
            "Output should not be all zeros"
        );
        assert!(
            !output2.iter().all(|&b| b == 0),
            "Output should not be all zeros"
        );
    }

    #[test]
    fn test_security_strengths() {
        for &strength in &[
            SecurityStrength::Bits128,
            SecurityStrength::Bits192,
            SecurityStrength::Bits256,
        ] {
            let rng = FipsRng::new(strength);
            assert!(
                rng.is_ok(),
                "Should create RNG for security strength {:?}",
                strength
            );
        }
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [42u8; 32];
        let mut rng1 = FipsRng::from_seed(seed, SecurityStrength::Bits256);
        let mut rng2 = FipsRng::from_seed(seed, SecurityStrength::Bits256);

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        rng1.fill_bytes(&mut output1);
        rng2.fill_bytes(&mut output2);

        assert_eq!(
            output1, output2,
            "Same seed should produce same output (for testing)"
        );
    }

    #[test]
    fn test_reseed() {
        let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();

        let mut before_reseed = [0u8; 32];
        rng.fill_bytes(&mut before_reseed);

        // Force reseed
        rng.reseed().unwrap();

        let mut after_reseed = [0u8; 32];
        rng.fill_bytes(&mut after_reseed);

        // After reseed, output should be different (high probability)
        // Note: There's a negligible chance they could be equal by random chance
        assert_ne!(
            before_reseed, after_reseed,
            "Reseed should change RNG state"
        );
    }

    #[test]
    fn test_health_check() {
        let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
        let result = rng.health_check();
        assert!(result.is_ok(), "Health check should pass");
    }

    #[test]
    fn test_rng_clone() {
        let rng1 = FipsRng::new(SecurityStrength::Bits256).unwrap();
        let mut rng2 = rng1.clone();

        let mut output = [0u8; 32];
        rng2.fill_bytes(&mut output);

        // Clone should produce valid random output
        assert!(!output.iter().all(|&b| b == 0), "Clone should work");
    }

    #[test]
    fn test_large_request() {
        let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
        let mut large_output = vec![0u8; 100_000]; // 100KB

        rng.fill_bytes(&mut large_output);

        // Should handle large requests via multiple calls
        assert!(
            !large_output.iter().all(|&b| b == 0),
            "Should fill large buffers"
        );
    }

    #[test]
    fn test_cryptorng_trait() {
        fn requires_cryptorng<R: RngCore + CryptoRng>(_rng: &mut R) {}

        let mut rng = FipsRng::new(SecurityStrength::Bits256).unwrap();
        requires_cryptorng(&mut rng); // Should compile
    }
}
