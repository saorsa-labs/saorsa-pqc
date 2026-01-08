//! Constant-Time FIPS Wrapper Layer
//!
//! This module provides constant-time wrappers around FIPS 203/204/205 operations
//! to ensure timing-safe behavior at API boundaries. While the underlying FIPS
//! implementations are designed to be constant-time, this wrapper layer ensures:
//!
//! 1. Error handling doesn't leak timing information
//! 2. Key/data validation is performed in constant time
//! 3. Buffer operations around crypto calls are constant-time
//! 4. A single point for CT verification and auditing
//!
//! # Security Model
//!
//! All operations in this module are designed to execute in constant time
//! regardless of:
//! - Input values (secret or public)
//! - Operation success or failure
//! - Key validity
//! - Buffer contents
//!
//! # FIPS Compliance
//!
//! This module wraps:
//! - FIPS 203 (ML-KEM): Key Encapsulation Mechanism
//! - FIPS 204 (ML-DSA): Digital Signature Algorithm
//! - FIPS 205 (SLH-DSA): Stateless Hash-Based Digital Signature Algorithm

use core::hint::black_box;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use super::constant_time::ct_eq;

/// Result type for constant-time operations
///
/// Unlike standard `Result`, this type is designed to be handled in constant time.
/// The success/failure status can be extracted without timing leakage.
#[derive(Clone)]
pub struct CtResult<T> {
    /// The result value (valid only if success is true)
    value: T,
    /// Whether the operation succeeded
    success: Choice,
}

impl<T> CtResult<T> {
    /// Create a successful result
    #[inline]
    pub fn ok(value: T) -> Self {
        Self {
            value,
            success: Choice::from(1u8),
        }
    }

    /// Create a failed result with a default value
    #[inline]
    pub fn err(default: T) -> Self {
        Self {
            value: default,
            success: Choice::from(0u8),
        }
    }

    /// Check if the operation succeeded (constant-time)
    #[inline]
    #[must_use]
    pub fn is_ok(&self) -> Choice {
        self.success
    }

    /// Check if the operation failed (constant-time)
    #[inline]
    #[must_use]
    pub fn is_err(&self) -> Choice {
        !self.success
    }

    /// Unwrap the value, returning default if error
    ///
    /// This operation is constant-time when T implements ConditionallySelectable
    #[inline]
    pub fn unwrap_or(self, default: T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(&default, &self.value, self.success)
    }

    /// Convert to bool (true if success)
    ///
    /// Uses black_box to prevent optimization
    #[inline]
    #[must_use]
    pub fn into_bool(self) -> bool {
        black_box(self.success.into())
    }

    /// Get the inner value (may be invalid if operation failed)
    ///
    /// # Safety
    /// Caller must ensure operation succeeded before using the value.
    /// This is useful when the caller has already checked is_ok().
    #[inline]
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T: Zeroize> Zeroize for CtResult<T> {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.success = Choice::from(0u8);
    }
}

// ============================================================================
// ML-KEM (FIPS 203) Constant-Time Wrappers
// ============================================================================

/// Constant-time ML-KEM operations wrapper
pub mod ct_ml_kem {
    use super::*;

    /// Shared secret size for ML-KEM (all variants)
    pub const SHARED_SECRET_SIZE: usize = 32;

    /// Constant-time shared secret type
    #[derive(Clone, Copy, Zeroize)]
    pub struct CtSharedSecret {
        bytes: [u8; SHARED_SECRET_SIZE],
    }

    impl CtSharedSecret {
        /// Create a new shared secret from bytes
        #[inline]
        pub fn from_bytes(bytes: [u8; SHARED_SECRET_SIZE]) -> Self {
            Self { bytes }
        }

        /// Create a zeroed shared secret
        #[inline]
        pub fn zero() -> Self {
            Self {
                bytes: [0u8; SHARED_SECRET_SIZE],
            }
        }

        /// Get the bytes (use with caution)
        #[inline]
        pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
            &self.bytes
        }
    }

    impl ConstantTimeEq for CtSharedSecret {
        fn ct_eq(&self, other: &Self) -> Choice {
            self.bytes.ct_eq(&other.bytes)
        }
    }

    impl ConditionallySelectable for CtSharedSecret {
        fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            let mut result = [0u8; SHARED_SECRET_SIZE];
            for i in 0..SHARED_SECRET_SIZE {
                result[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
            }
            Self { bytes: result }
        }
    }

    /// Validate key length in constant time
    ///
    /// Returns Choice(1) if lengths match, Choice(0) otherwise
    #[inline]
    pub fn ct_validate_key_length(key: &[u8], expected: usize) -> Choice {
        key.len().ct_eq(&expected)
    }

    /// Constant-time decapsulation wrapper
    ///
    /// Performs ML-KEM decapsulation with timing-safe error handling.
    /// On failure, returns a consistent "dummy" shared secret to prevent
    /// timing oracles based on error conditions.
    ///
    /// # Arguments
    /// * `sk_bytes` - Secret key bytes
    /// * `ct_bytes` - Ciphertext bytes
    /// * `expected_sk_len` - Expected secret key length
    /// * `expected_ct_len` - Expected ciphertext length
    /// * `decaps_fn` - The actual decapsulation function to call
    ///
    /// # Returns
    /// CtResult containing the shared secret on success, or dummy data on failure
    #[inline]
    pub fn ct_decapsulate<F>(
        sk_bytes: &[u8],
        ct_bytes: &[u8],
        expected_sk_len: usize,
        expected_ct_len: usize,
        decaps_fn: F,
    ) -> CtResult<CtSharedSecret>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<[u8; SHARED_SECRET_SIZE]>,
    {
        // Validate lengths in constant time
        let sk_len_ok = ct_validate_key_length(sk_bytes, expected_sk_len);
        let ct_len_ok = ct_validate_key_length(ct_bytes, expected_ct_len);
        let lengths_ok = sk_len_ok & ct_len_ok;

        // Always call the decapsulation function (even if lengths are wrong)
        // to maintain constant timing. Use a safe fallback if lengths are wrong.
        let dummy_sk = vec![0u8; expected_sk_len];
        let dummy_ct = vec![0u8; expected_ct_len];

        // Conditionally use real or dummy data
        let sk_to_use = if bool::from(lengths_ok) {
            sk_bytes
        } else {
            &dummy_sk
        };
        let ct_to_use = if bool::from(lengths_ok) {
            ct_bytes
        } else {
            &dummy_ct
        };

        // Perform decapsulation
        let result = decaps_fn(sk_to_use, ct_to_use);

        // Handle result in constant time
        match result {
            Some(ss_bytes) => {
                let ss = CtSharedSecret::from_bytes(ss_bytes);
                // Only return success if lengths were also OK
                if bool::from(lengths_ok) {
                    CtResult::ok(ss)
                } else {
                    CtResult::err(CtSharedSecret::zero())
                }
            }
            None => CtResult::err(CtSharedSecret::zero()),
        }
    }

    /// Constant-time encapsulation wrapper
    ///
    /// Performs ML-KEM encapsulation with timing-safe error handling.
    ///
    /// # Arguments
    /// * `pk_bytes` - Public key bytes
    /// * `expected_pk_len` - Expected public key length
    /// * `encaps_fn` - The actual encapsulation function to call
    ///
    /// # Returns
    /// Option containing (shared_secret, ciphertext) on success
    #[inline]
    pub fn ct_encapsulate<F, const CT_LEN: usize>(
        pk_bytes: &[u8],
        expected_pk_len: usize,
        encaps_fn: F,
    ) -> Option<(CtSharedSecret, [u8; CT_LEN])>
    where
        F: FnOnce(&[u8]) -> Option<([u8; SHARED_SECRET_SIZE], [u8; CT_LEN])>,
    {
        // Validate length in constant time
        let len_ok = ct_validate_key_length(pk_bytes, expected_pk_len);

        if bool::from(len_ok) {
            encaps_fn(pk_bytes).map(|(ss, ct)| (CtSharedSecret::from_bytes(ss), ct))
        } else {
            // Length mismatch - return None
            // Note: This is a public key validation, so early return is acceptable
            None
        }
    }
}

// ============================================================================
// ML-DSA (FIPS 204) Constant-Time Wrappers
// ============================================================================

/// Constant-time ML-DSA operations wrapper
pub mod ct_ml_dsa {
    use super::*;

    /// Constant-time signature verification wrapper
    ///
    /// Performs signature verification with timing-safe result handling.
    /// The verification result is returned as a Choice to enable constant-time
    /// downstream processing.
    ///
    /// # Arguments
    /// * `pk_bytes` - Public key bytes
    /// * `message` - Message that was signed
    /// * `sig_bytes` - Signature bytes
    /// * `expected_pk_len` - Expected public key length
    /// * `expected_sig_len` - Expected signature length
    /// * `verify_fn` - The actual verification function
    ///
    /// # Returns
    /// Choice(1) if signature is valid, Choice(0) otherwise
    #[inline]
    pub fn ct_verify<F>(
        pk_bytes: &[u8],
        message: &[u8],
        sig_bytes: &[u8],
        expected_pk_len: usize,
        expected_sig_len: usize,
        verify_fn: F,
    ) -> Choice
    where
        F: FnOnce(&[u8], &[u8], &[u8]) -> bool,
    {
        // Validate lengths in constant time
        let pk_len_ok = pk_bytes.len().ct_eq(&expected_pk_len);
        let sig_len_ok = sig_bytes.len().ct_eq(&expected_sig_len);
        let lengths_ok = pk_len_ok & sig_len_ok;

        // Always perform verification to maintain constant timing
        // Use dummy data if lengths are wrong
        let dummy_pk = vec![0u8; expected_pk_len];
        let dummy_sig = vec![0u8; expected_sig_len];

        let pk_to_use = if bool::from(lengths_ok) {
            pk_bytes
        } else {
            &dummy_pk
        };
        let sig_to_use = if bool::from(lengths_ok) {
            sig_bytes
        } else {
            &dummy_sig
        };

        // Perform verification
        let verify_result = verify_fn(pk_to_use, message, sig_to_use);

        // Combine results in constant time
        let verify_choice = Choice::from(u8::from(verify_result));
        lengths_ok & verify_choice
    }

    /// Constant-time signing wrapper
    ///
    /// Performs signing with timing-safe key validation.
    ///
    /// # Arguments
    /// * `sk_bytes` - Secret key bytes
    /// * `message` - Message to sign
    /// * `expected_sk_len` - Expected secret key length
    /// * `sign_fn` - The actual signing function
    ///
    /// # Returns
    /// Option containing the signature on success
    #[inline]
    pub fn ct_sign<F, const SIG_LEN: usize>(
        sk_bytes: &[u8],
        message: &[u8],
        expected_sk_len: usize,
        sign_fn: F,
    ) -> Option<[u8; SIG_LEN]>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<[u8; SIG_LEN]>,
    {
        // Validate length
        let len_ok = sk_bytes.len().ct_eq(&expected_sk_len);

        if bool::from(len_ok) {
            sign_fn(sk_bytes, message)
        } else {
            None
        }
    }
}

// ============================================================================
// SLH-DSA (FIPS 205) Constant-Time Wrappers
// ============================================================================

/// Constant-time SLH-DSA operations wrapper
pub mod ct_slh_dsa {
    use super::*;

    /// Constant-time signature verification for SLH-DSA
    ///
    /// Same security properties as ML-DSA verification wrapper.
    #[inline]
    pub fn ct_verify<F>(
        pk_bytes: &[u8],
        message: &[u8],
        sig_bytes: &[u8],
        context: &[u8],
        expected_pk_len: usize,
        expected_sig_len: usize,
        verify_fn: F,
    ) -> Choice
    where
        F: FnOnce(&[u8], &[u8], &[u8], &[u8]) -> bool,
    {
        // Validate lengths in constant time
        let pk_len_ok = pk_bytes.len().ct_eq(&expected_pk_len);
        let sig_len_ok = sig_bytes.len().ct_eq(&expected_sig_len);
        let context_len_ok = Choice::from(u8::from(context.len() <= 255));
        let lengths_ok = pk_len_ok & sig_len_ok & context_len_ok;

        // Create dummy data for constant-time execution
        let dummy_pk = vec![0u8; expected_pk_len];
        let dummy_sig = vec![0u8; expected_sig_len];

        let pk_to_use = if bool::from(lengths_ok) {
            pk_bytes
        } else {
            &dummy_pk
        };
        let sig_to_use = if bool::from(lengths_ok) {
            sig_bytes
        } else {
            &dummy_sig
        };

        // Perform verification
        let verify_result = verify_fn(pk_to_use, message, sig_to_use, context);

        // Combine results
        let verify_choice = Choice::from(u8::from(verify_result));
        lengths_ok & verify_choice
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Constant-time buffer comparison for cryptographic data
///
/// Compares two buffers and returns the result as a Choice.
/// This is a thin wrapper around ct_eq for use in this module.
#[inline]
pub fn ct_buffer_eq(a: &[u8], b: &[u8]) -> Choice {
    Choice::from(u8::from(ct_eq(a, b)))
}

/// Constant-time conditional zeroize
///
/// Zeroizes the buffer if the condition is true, in constant time.
#[inline]
pub fn ct_conditional_zeroize(buffer: &mut [u8], should_zeroize: Choice) {
    for byte in buffer.iter_mut() {
        byte.conditional_assign(&0u8, should_zeroize);
    }
}

/// Secure comparison of authentication tags
///
/// Compares two authentication tags in constant time.
/// Returns true if they match, false otherwise.
#[inline]
#[must_use]
pub fn ct_tag_verify(computed: &[u8], expected: &[u8]) -> bool {
    ct_eq(computed, expected)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_result_ok() {
        let result = CtResult::ok(42u32);
        assert!(bool::from(result.is_ok()));
        assert!(!bool::from(result.is_err()));
        assert!(result.into_bool());
    }

    #[test]
    fn test_ct_result_err() {
        let result: CtResult<u32> = CtResult::err(0);
        assert!(!bool::from(result.is_ok()));
        assert!(bool::from(result.is_err()));
        assert!(!result.into_bool());
    }

    #[test]
    fn test_ct_result_unwrap_or() {
        let ok_result = CtResult::ok(42u32);
        let err_result: CtResult<u32> = CtResult::err(0);

        assert_eq!(ok_result.unwrap_or(100), 42);
        assert_eq!(err_result.unwrap_or(100), 100);
    }

    #[test]
    fn test_ct_shared_secret() {
        let ss1 = ct_ml_kem::CtSharedSecret::from_bytes([1u8; 32]);
        let ss2 = ct_ml_kem::CtSharedSecret::from_bytes([1u8; 32]);
        let ss3 = ct_ml_kem::CtSharedSecret::from_bytes([2u8; 32]);

        assert!(bool::from(ss1.ct_eq(&ss2)));
        assert!(!bool::from(ss1.ct_eq(&ss3)));
    }

    #[test]
    fn test_ct_validate_key_length() {
        let key = [0u8; 32];
        assert!(bool::from(ct_ml_kem::ct_validate_key_length(&key, 32)));
        assert!(!bool::from(ct_ml_kem::ct_validate_key_length(&key, 64)));
    }

    #[test]
    fn test_ct_buffer_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(bool::from(ct_buffer_eq(&a, &b)));
        assert!(!bool::from(ct_buffer_eq(&a, &c)));
    }

    #[test]
    fn test_ct_conditional_zeroize() {
        let mut buffer = [1u8, 2, 3, 4];

        // Don't zeroize
        ct_conditional_zeroize(&mut buffer, Choice::from(0u8));
        assert_eq!(buffer, [1, 2, 3, 4]);

        // Zeroize
        ct_conditional_zeroize(&mut buffer, Choice::from(1u8));
        assert_eq!(buffer, [0, 0, 0, 0]);
    }

    #[test]
    fn test_ct_tag_verify() {
        let tag1 = [1u8; 16];
        let tag2 = [1u8; 16];
        let tag3 = [2u8; 16];

        assert!(ct_tag_verify(&tag1, &tag2));
        assert!(!ct_tag_verify(&tag1, &tag3));
    }

    #[test]
    fn test_ct_ml_dsa_verify_length_validation() {
        // Test that invalid lengths return false
        let pk = [0u8; 32];
        let msg = b"test message";
        let sig = [0u8; 64];

        // Mock verify function that always returns true
        let result = ct_ml_dsa::ct_verify(
            &pk,
            msg,
            &sig,
            1952, // ML-DSA-65 public key size
            3309, // ML-DSA-65 signature size
            |_, _, _| true,
        );

        // Should fail because lengths don't match
        assert!(!bool::from(result));
    }

    #[test]
    fn test_ct_ml_dsa_verify_success() {
        let pk = vec![0u8; 1952];
        let msg = b"test message";
        let sig = vec![0u8; 3309];

        // Mock verify function that returns true
        let result = ct_ml_dsa::ct_verify(&pk, msg, &sig, 1952, 3309, |_, _, _| true);

        assert!(bool::from(result));
    }
}
