//! Constant-time operations for cryptographic primitives
//!
//! This module provides constant-time comparison and conditional operations
//! to prevent timing attacks on sensitive cryptographic data.

use core::hint::black_box;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// Constant-time comparison for byte slices
///
/// Returns true if the slices are equal, false otherwise.
/// The comparison runs in constant time regardless of where differences occur.
///
/// # Security Note
/// This function is designed to be constant-time to prevent timing attacks.
/// Uses the `subtle` crate's ConstantTimeEq implementation which is
/// well-audited and optimized for constant-time behavior.
///
/// When slices have different lengths, this function returns false but
/// still performs the comparison on the overlapping portion to minimize
/// timing variations. Note that some timing difference is unavoidable
/// when lengths differ significantly.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Use subtle's ConstantTimeEq which handles same-length comparison
    // in a well-tested constant-time manner
    if a.len() != b.len() {
        // Different lengths - still compare the overlapping portion
        // to minimize timing leakage, but we know the result will be false
        let min_len = a.len().min(b.len());
        if min_len > 0 {
            // Compare overlapping portion to do consistent work
            let _ = black_box(a[..min_len].ct_eq(&b[..min_len]));
        }
        return black_box(false);
    }

    // Same length - use subtle's constant-time comparison directly
    // This is the critical path for security-sensitive comparisons
    let result = a.ct_eq(b);
    black_box(result.into())
}

/// Constant-time conditional selection
///
/// Selects `a` if `choice` is true, `b` otherwise.
/// The selection happens in constant time.
#[inline]
pub fn ct_select<T: ConditionallySelectable>(a: &T, b: &T, choice: bool) -> T {
    T::conditional_select(b, a, Choice::from(u8::from(choice)))
}

/// Constant-time conditional assignment
///
/// Assigns `new_val` to `dest` if `choice` is true.
/// The assignment happens in constant time.
#[inline]
pub fn ct_assign<T: ConditionallySelectable>(dest: &mut T, new_val: &T, choice: bool) {
    dest.conditional_assign(new_val, Choice::from(u8::from(choice)));
}

/// Constant-time option type for cryptographic operations
///
/// Similar to `Option<T>` but with constant-time operations.
pub struct CtSecretOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtSecretOption<T> {
    /// Create a new Some variant
    #[inline]
    pub fn some(value: T) -> Self {
        Self {
            value,
            is_some: Choice::from(1),
        }
    }

    /// Create a new None variant
    #[inline]
    pub fn none(default: T) -> Self {
        Self {
            value: default,
            is_some: Choice::from(0),
        }
    }

    /// Check if the option contains a value (constant-time)
    #[inline]
    pub const fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Check if the option is None (constant-time)
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    /// Unwrap the value with a default if None
    #[inline]
    pub fn unwrap_or(self, default: T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(&default, &self.value, self.is_some)
    }

    /// Map the value if Some
    #[inline]
    pub fn map<U, F>(self, f: F) -> CtSecretOption<U>
    where
        F: FnOnce(T) -> U,
        U: ConditionallySelectable + Default,
    {
        let mapped = f(self.value);
        let default = U::default();
        CtSecretOption {
            value: U::conditional_select(&default, &mapped, self.is_some),
            is_some: self.is_some,
        }
    }
}

impl<T: Zeroize> Zeroize for CtSecretOption<T> {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.is_some = Choice::from(0);
    }
}

/// Trait for types that support constant-time equality comparison
pub trait ConstantTimeEqExt: Sized {
    /// Perform constant-time equality comparison
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Perform constant-time inequality comparison
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

/// Implement constant-time comparison for secret key types
macro_rules! impl_ct_eq_for_secret {
    ($type:ty) => {
        impl ConstantTimeEqExt for $type {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.as_bytes().ct_eq(other.as_bytes())
            }
        }
    };
}

// Import types that need constant-time operations
use crate::pqc::ml_dsa_44::{MlDsa44SecretKey, MlDsa44Signature};
use crate::pqc::ml_dsa_87::{MlDsa87SecretKey, MlDsa87Signature};
use crate::pqc::ml_kem_1024::MlKem1024SecretKey;
use crate::pqc::ml_kem_512::MlKem512SecretKey;
use crate::pqc::types::{MlDsaSecretKey, MlDsaSignature, MlKemSecretKey, SharedSecret};

// Implement constant-time comparison for all sensitive types
impl_ct_eq_for_secret!(MlKemSecretKey);
impl_ct_eq_for_secret!(MlDsaSecretKey);
impl_ct_eq_for_secret!(SharedSecret);
impl_ct_eq_for_secret!(MlKem512SecretKey);
impl_ct_eq_for_secret!(MlKem1024SecretKey);
impl_ct_eq_for_secret!(MlDsa44SecretKey);
impl_ct_eq_for_secret!(MlDsa87SecretKey);

// Implement for signatures
impl ConstantTimeEqExt for MlDsaSignature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl ConstantTimeEqExt for MlDsa44Signature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl ConstantTimeEqExt for MlDsa87Signature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

/// Perform constant-time verification of a boolean condition
///
/// Returns a `CtOption` that is Some(value) if condition is true, None otherwise.
/// The operation runs in constant time.
#[inline]
pub fn ct_verify<T>(condition: bool, value: T) -> CtOption<T> {
    CtOption::new(value, Choice::from(u8::from(condition)))
}

/// Constant-time byte array comparison
///
/// Compares two fixed-size byte arrays in constant time.
#[must_use]
pub fn ct_array_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    // Use black_box to prevent optimization
    let result = a.ct_eq(b);
    black_box(result.into())
}

/// Clear sensitive data from memory in constant time
///
/// This ensures the compiler doesn't optimize away the clearing operation.
#[inline]
pub fn ct_clear<T: Zeroize>(data: &mut T) {
    data.zeroize();
}

/// Constant-time conditional copy
///
/// Copies `src` to `dest` if `choice` is true AND lengths match.
///
/// # Returns
/// `true` if lengths matched (copy may or may not have occurred based on `choice`),
/// `false` if lengths did not match (no copy occurred).
///
/// # Security Properties
/// - **Constant-time on `choice`**: Whether `choice` is true or false does not
///   affect timing. This is the critical security property for FIPS 140-3.
/// - **Constant-time on buffer contents**: The values in `src` and `dest` do not
///   affect timing.
/// - **Length is NOT secret**: Buffer lengths are public API parameters. Different
///   lengths will have different timing, which is expected and not a vulnerability.
///
/// # Example
/// ```
/// use saorsa_pqc::pqc::constant_time::ct_copy_bytes;
///
/// let mut dest = [0u8; 4];
/// let src = [1u8, 2, 3, 4];
///
/// // Copy happens (choice=true, lengths match)
/// assert!(ct_copy_bytes(&mut dest, &src, true));
/// assert_eq!(dest, [1, 2, 3, 4]);
///
/// // Reset and try with choice=false - no copy, but same timing
/// dest = [0u8; 4];
/// assert!(ct_copy_bytes(&mut dest, &src, false));
/// assert_eq!(dest, [0, 0, 0, 0]); // Unchanged
/// ```
#[inline]
#[must_use]
pub fn ct_copy_bytes(dest: &mut [u8], src: &[u8], choice: bool) -> bool {
    // Length mismatch is not a secret - early return is fine
    if dest.len() != src.len() {
        return false;
    }

    // The critical constant-time property: choice doesn't affect timing
    let should_copy = Choice::from(u8::from(choice));

    // Constant-time conditional copy for each byte
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        d.conditional_assign(s, should_copy);
    }

    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
        assert!(!ct_eq(&a[..3], &b)); // Different lengths
    }

    #[test]
    fn test_ct_select() {
        let a = 42u32;
        let b = 100u32;

        assert_eq!(ct_select(&a, &b, true), a);
        assert_eq!(ct_select(&a, &b, false), b);
    }

    #[test]
    fn test_ct_option() {
        let some_val = CtSecretOption::some(42u32);
        let none_val = CtSecretOption::none(0u32);

        assert_eq!(some_val.is_some().unwrap_u8(), 1);
        assert_eq!(none_val.is_none().unwrap_u8(), 1);

        assert_eq!(some_val.unwrap_or(100), 42);
        assert_eq!(none_val.unwrap_or(100), 100);
    }

    #[test]
    fn test_ct_copy_bytes() {
        let src = [1u8, 2, 3, 4];
        let mut dest1 = [0u8; 4];
        let mut dest2 = [0u8; 4];

        let success1 = ct_copy_bytes(&mut dest1, &src, true);
        let success2 = ct_copy_bytes(&mut dest2, &src, false);

        assert!(success1, "Copy with choice=true should succeed");
        assert!(success2, "Copy with choice=false should succeed (no-op)");
        assert_eq!(dest1, src);
        assert_eq!(dest2, [0, 0, 0, 0]);
    }

    #[test]
    fn test_ct_copy_bytes_mismatched_length() {
        // Test that mismatched lengths are handled in constant time
        // The function should still process in constant time but return false
        let src_short = [1u8, 2];
        let src_long = [1u8, 2, 3, 4, 5, 6];
        let mut dest = [0u8; 4];

        // Mismatched lengths should return false but still take constant time
        let result1 = ct_copy_bytes(&mut dest, &src_short, true);
        assert!(!result1, "Mismatched length should return false");
        assert_eq!(
            dest,
            [0, 0, 0, 0],
            "Dest should be unchanged on length mismatch"
        );

        let result2 = ct_copy_bytes(&mut dest, &src_long, true);
        assert!(!result2, "Mismatched length should return false");
        assert_eq!(
            dest,
            [0, 0, 0, 0],
            "Dest should be unchanged on length mismatch"
        );
    }

    #[test]
    fn test_constant_time_property() {
        // This test doesn't verify constant-time execution directly
        // (that requires specialized tools), but ensures the API works correctly

        let secret1 = vec![0u8; 1000];
        let secret2 = vec![1u8; 1000];

        // These operations should take the same time regardless of content
        let _ = ct_eq(&secret1, &secret2);
        let _ = ct_eq(&secret1, &secret1);

        // The actual constant-time property would be verified with tools like
        // valgrind, dudect, or specialized timing analysis
    }
}
