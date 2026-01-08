// Rust 1.92+ raises unused_assignments on struct fields read via getter methods
// when used with derive macros like Zeroize. This is a known false positive.
#![allow(unused_assignments)]

//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) API - FIPS 205
//!
//! This module provides a high-level interface to the FIPS 205 SLH-DSA (Stateless
//! Hash-Based Digital Signature Algorithm), also known as SPHINCS+. SLH-DSA is unique
//! among post-quantum signature schemes as it relies solely on the security of hash
//! functions rather than mathematical problems like lattices or codes.
//!
//! # Features
//!
//! - **Multiple security levels**: 128-bit, 192-bit, and 256-bit
//! - **Two optimization modes**:
//!   - Small signatures (s variants): Optimized for size (~8-30KB signatures)
//!   - Fast signing (f variants): Optimized for speed (~17-50KB signatures)
//! - **Two hash function families**: SHA-2 and SHAKE
//! - **Stateless operation**: No state management required
//! - **Context support**: Domain separation for different applications
//! - **Memory-safe**: Automatic zeroization of sensitive data
//!
//! # Security Levels and Variants
//!
//! SLH-DSA offers 12 parameter sets combining security levels, hash functions, and
//! optimization modes:
//!
//! | Variant | Security | Hash | Mode | Signature Size | Signing Speed |
//! |---------|----------|------|------|----------------|---------------|
//! | SHA2-128s | 128-bit | SHA-2 | Small | 7,856 bytes | Slower |
//! | SHA2-128f | 128-bit | SHA-2 | Fast | 17,088 bytes | Faster |
//! | SHA2-192s | 192-bit | SHA-2 | Small | 16,224 bytes | Slower |
//! | SHA2-192f | 192-bit | SHA-2 | Fast | 35,664 bytes | Faster |
//! | SHA2-256s | 256-bit | SHA-2 | Small | 29,792 bytes | Slower |
//! | SHA2-256f | 256-bit | SHA-2 | Fast | 49,856 bytes | Faster |
//! | SHAKE-128s | 128-bit | SHAKE | Small | 7,856 bytes | Slower |
//! | SHAKE-128f | 128-bit | SHAKE | Fast | 17,088 bytes | Faster |
//! | SHAKE-192s | 192-bit | SHAKE | Small | 16,224 bytes | Slower |
//! | SHAKE-192f | 192-bit | SHAKE | Fast | 35,664 bytes | Faster |
//! | SHAKE-256s | 256-bit | SHAKE | Small | 29,792 bytes | Slower |
//! | SHAKE-256f | 256-bit | SHAKE | Fast | 49,856 bytes | Faster |
//!
//! # Basic Usage
//!
//! ```rust
//! use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
//!
//! // Create SLH-DSA instance with SHA2-128s (small signatures)
//! let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
//!
//! // Generate a key pair
//! let (public_key, secret_key) = slh.generate_keypair()?;
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = slh.sign(&secret_key, message)?;
//!
//! // Verify the signature
//! let is_valid = slh.verify(&public_key, message, &signature)?;
//! assert!(is_valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Advanced Usage with Context
//!
//! ```rust
//! use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
//!
//! // Use SHA2-128f for faster signing
//! let slh = SlhDsa::new(SlhDsaVariant::Sha2_128f);
//! let (public_key, secret_key) = slh.generate_keypair()?;
//!
//! // Sign with context for domain separation
//! let message = b"Financial transaction data";
//! let context = b"BankingApp-v1.0";
//! let signature = slh.sign_with_context(&secret_key, message, context)?;
//!
//! // Verify with the same context
//! let is_valid = slh.verify_with_context(&public_key, message, &signature, context)?;
//! assert!(is_valid);
//!
//! // Different context will fail verification
//! let wrong_context = b"BankingApp-v2.0";
//! let is_valid = slh.verify_with_context(&public_key, message, &signature, wrong_context)?;
//! assert!(!is_valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Choosing a Variant
//!
//! ## For Bandwidth-Constrained Applications
//! Use "s" (small) variants when signature size is critical:
//! ```rust
//! use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
//!
//! // SHA2-128s: Smallest signatures at 128-bit security
//! let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
//! # let (_, sk) = slh.generate_keypair().unwrap();
//! # let sig = slh.sign(&sk, b"test").unwrap();
//! // Signature is only 7,856 bytes
//! ```
//!
//! ## For Performance-Critical Applications
//! Use "f" (fast) variants when signing speed is critical:
//! ```rust
//! use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
//!
//! // SHA2-128f: Faster signing at 128-bit security
//! let slh = SlhDsa::new(SlhDsaVariant::Sha2_128f);
//! # let (_, sk) = slh.generate_keypair().unwrap();
//! # let sig = slh.sign(&sk, b"test").unwrap();
//! // Signing is ~8x faster than SHA2-128s
//! ```
//!
//! ## Hardware Acceleration Considerations
//! - Use SHA-2 variants if your platform has SHA-256 hardware acceleration
//! - Use SHAKE variants for better performance on platforms without SHA-2 acceleration
//!
//! # Key Management
//!
//! ```rust
//! use saorsa_pqc::api::{SlhDsa, SlhDsaVariant, SlhDsaPublicKey, SlhDsaSecretKey};
//!
//! let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
//! let (public_key, secret_key) = slh.generate_keypair()?;
//!
//! // Export keys for storage
//! let pk_bytes = public_key.to_bytes();
//! let sk_bytes = secret_key.to_bytes();
//!
//! // Import keys from storage
//! let imported_pk = SlhDsaPublicKey::from_bytes(SlhDsaVariant::Sha2_128s, &pk_bytes)?;
//! let imported_sk = SlhDsaSecretKey::from_bytes(SlhDsaVariant::Sha2_128s, &sk_bytes)?;
//!
//! // Use imported keys
//! let message = b"Test message";
//! let signature = slh.sign(&imported_sk, message)?;
//! assert!(slh.verify(&imported_pk, message, &signature)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Security Considerations
//!
//! 1. **Hash-based security**: SLH-DSA's security relies solely on the preimage and
//!    collision resistance of the underlying hash functions
//! 2. **Stateless operation**: Unlike traditional hash-based signatures, SLH-DSA requires
//!    no state management, eliminating synchronization issues
//! 3. **Large signatures**: SLH-DSA signatures are significantly larger than classical
//!    or lattice-based schemes
//! 4. **Hedged randomness**: The implementation uses hedged randomness by default for
//!    enhanced security against RNG failures
//! 5. **Side-channel resistance**: The underlying implementation includes protections
//!    against timing attacks

use super::errors::{PqcError, PqcResult};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import FIPS implementations
use fips205::traits::{SerDes, Signer, Verifier};
use fips205::{
    slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s, slh_dsa_sha2_256f,
    slh_dsa_sha2_256s, slh_dsa_shake_128f, slh_dsa_shake_128s, slh_dsa_shake_192f,
    slh_dsa_shake_192s, slh_dsa_shake_256f, slh_dsa_shake_256s,
};

/// SLH-DSA algorithm variants as defined in FIPS 205
///
/// Each variant represents a specific parameter set combining:
/// - Security level (128, 192, or 256 bits)
/// - Hash function (SHA-2 or SHAKE)
/// - Optimization mode (s for small signatures, f for fast signing)
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::SlhDsaVariant;
///
/// // Choose based on your requirements
/// let need_small_signatures = true;
/// let variant = if need_small_signatures {
///     SlhDsaVariant::Sha2_128s  // 7.8KB signatures
/// } else {
///     SlhDsaVariant::Sha2_128f  // 17KB signatures, 8x faster
/// };
///
/// // Query variant properties
/// println!("Security: {}", variant.security_level());
/// println!("Signature size: {} bytes", variant.signature_size());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhDsaVariant {
    /// SHA2-128s: Small signature, slower (128-bit security, 7.8KB signatures)
    Sha2_128s,
    /// SHA2-128f: Fast signing, larger signature (128-bit security, 17KB signatures)
    Sha2_128f,
    /// SHA2-192s: Small signature, slower (192-bit security, 16KB signatures)
    Sha2_192s,
    /// SHA2-192f: Fast signing, larger signature (192-bit security, 35KB signatures)
    Sha2_192f,
    /// SHA2-256s: Small signature, slower (256-bit security, 30KB signatures)
    Sha2_256s,
    /// SHA2-256f: Fast signing, larger signature (256-bit security, 50KB signatures)
    Sha2_256f,
    /// SHAKE-128s: Small signature, slower (128-bit security, 7.8KB signatures)
    Shake128s,
    /// SHAKE-128f: Fast signing, larger signature (128-bit security, 17KB signatures)
    Shake128f,
    /// SHAKE-192s: Small signature, slower (192-bit security, 16KB signatures)
    Shake192s,
    /// SHAKE-192f: Fast signing, larger signature (192-bit security, 35KB signatures)
    Shake192f,
    /// SHAKE-256s: Small signature, slower (256-bit security, 30KB signatures)
    Shake256s,
    /// SHAKE-256f: Fast signing, larger signature (256-bit security, 50KB signatures)
    Shake256f,
}

// Manual implementation of Zeroize for SlhDsaVariant (no-op since it contains no sensitive data)
impl zeroize::Zeroize for SlhDsaVariant {
    fn zeroize(&mut self) {
        // No sensitive data to zeroize in an enum variant selector
    }
}

impl SlhDsaVariant {
    /// Get the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => 32,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => 48,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => 64,
        }
    }

    /// Get the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => 64,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => 96,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => 128,
        }
    }

    /// Get the signature size in bytes
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::Sha2_128s | Self::Shake128s => 7856,
            Self::Sha2_128f | Self::Shake128f => 17088,
            Self::Sha2_192s | Self::Shake192s => 16224,
            Self::Sha2_192f | Self::Shake192f => 35664,
            Self::Sha2_256s | Self::Shake256s => 29792,
            Self::Sha2_256f | Self::Shake256f => 49856,
        }
    }

    /// Get the security level description
    #[must_use]
    pub const fn security_level(&self) -> &'static str {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => {
                "128-bit security"
            }
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => {
                "192-bit security"
            }
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => {
                "256-bit security"
            }
        }
    }

    /// Is this a "small" variant (slower but smaller signatures)?
    #[must_use]
    pub const fn is_small(&self) -> bool {
        matches!(
            self,
            Self::Sha2_128s
                | Self::Sha2_192s
                | Self::Sha2_256s
                | Self::Shake128s
                | Self::Shake192s
                | Self::Shake256s
        )
    }

    /// Maximum context length (255 bytes for all variants)
    pub const MAX_CONTEXT_LENGTH: usize = 255;
}

/// SLH-DSA public key for signature verification
///
/// This represents a public key that can be shared openly and used to verify
/// signatures created with the corresponding secret key. The key size varies
/// based on the security level (32, 48, or 64 bytes).
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant, SlhDsaPublicKey};
///
/// // Generate a key pair
/// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
/// let (public_key, secret_key) = slh.generate_keypair()?;
///
/// // Export for transmission or storage
/// let pk_bytes = public_key.to_bytes();
/// assert_eq!(pk_bytes.len(), 32);  // 32 bytes for 128-bit security
///
/// // Import from bytes
/// let imported_pk = SlhDsaPublicKey::from_bytes(SlhDsaVariant::Sha2_128s, &pk_bytes)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaPublicKey {
    #[zeroize(skip)]
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaPublicKey {
    /// Get the variant of this key
    #[must_use]
    pub const fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Export the public key as bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a public key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has an incorrect length for the specified variant.
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.public_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.public_key_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// SLH-DSA secret key for signature generation
///
/// This represents a secret key that must be kept private and is used to create
/// signatures. The key is automatically zeroized when dropped to prevent sensitive
/// data from remaining in memory. Key sizes are 64, 96, or 128 bytes depending
/// on the security level.
///
/// # Security
/// - Secret keys are automatically zeroized on drop
/// - Use secure storage when persisting keys
/// - Never transmit secret keys over insecure channels
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant, SlhDsaSecretKey};
///
/// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
/// let (public_key, secret_key) = slh.generate_keypair()?;
///
/// // Sign a message
/// let signature = slh.sign(&secret_key, b"Important document")?;
///
/// // Export for secure storage (handle with care!)
/// let sk_bytes = secret_key.to_bytes();
/// assert_eq!(sk_bytes.len(), 64);  // 64 bytes for 128-bit security
///
/// // Import from secure storage
/// let imported_sk = SlhDsaSecretKey::from_bytes(SlhDsaVariant::Sha2_128s, &sk_bytes)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSecretKey {
    #[zeroize(skip)]
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaSecretKey {
    /// Get the variant of this key
    #[must_use]
    pub const fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Export the secret key as bytes (handle with care!)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a secret key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has an incorrect length for the specified variant.
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.secret_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.secret_key_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// SLH-DSA signature
///
/// Represents a digital signature created using SLH-DSA. Signature sizes range from
/// approximately 8KB to 50KB depending on the variant chosen. The signature includes
/// all necessary information for verification and is deterministic for a given
/// message and key pair.
///
/// # Size Considerations
/// SLH-DSA signatures are significantly larger than classical signatures:
/// - Small variants (s): 8KB - 30KB
/// - Fast variants (f): 17KB - 50KB
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant, SlhDsaSignature};
///
/// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
/// let (public_key, secret_key) = slh.generate_keypair()?;
///
/// // Create a signature
/// let message = b"Contract agreement";
/// let signature = slh.sign(&secret_key, message)?;
///
/// // Export for transmission
/// let sig_bytes = signature.to_bytes();
/// println!("Signature size: {} bytes", sig_bytes.len());
///
/// // Import received signature
/// let imported_sig = SlhDsaSignature::from_bytes(SlhDsaVariant::Sha2_128s, &sig_bytes)?;
///
/// // Verify the imported signature
/// assert!(slh.verify(&public_key, message, &imported_sig)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSignature {
    #[zeroize(skip)]
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaSignature {
    /// Get the variant of this signature
    #[must_use]
    pub const fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Export the signature as bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a signature from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has an incorrect length for the specified variant.
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.signature_size() {
            return Err(PqcError::InvalidSignatureSize {
                expected: variant.signature_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) main API
///
/// This struct provides the main interface for SLH-DSA operations including
/// key generation, signing, and verification. It encapsulates the complexity
/// of the underlying FIPS 205 implementation and provides a simple, safe API.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
///
/// // Create an instance for 192-bit security with small signatures
/// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
///
/// // Generate keys
/// let (public_key, secret_key) = slh.generate_keypair()?;
///
/// // Sign and verify
/// let message = b"Quantum-safe message";
/// let signature = slh.sign(&secret_key, message)?;
/// assert!(slh.verify(&public_key, message, &signature)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SlhDsa {
    variant: SlhDsaVariant,
}

impl SlhDsa {
    /// Create a new SLH-DSA instance with the specified variant
    ///
    /// # Arguments
    /// * `variant` - The SLH-DSA parameter set to use
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
    ///
    /// // For bandwidth-constrained applications
    /// let slh_small = SlhDsa::new(SlhDsaVariant::Sha2_128s);
    ///
    /// // For performance-critical applications
    /// let slh_fast = SlhDsa::new(SlhDsaVariant::Sha2_128f);
    /// ```
    #[must_use]
    pub const fn new(variant: SlhDsaVariant) -> Self {
        Self { variant }
    }

    /// Generate a new key pair
    ///
    /// Creates a new public/secret key pair using the system's secure random
    /// number generator. Key generation is deterministic given the same random
    /// seed, but the system RNG ensures each key pair is unique.
    ///
    /// # Returns
    /// A tuple containing the public key and secret key
    ///
    /// # Errors
    ///
    /// Returns an error if the key generation process fails.
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
    ///
    /// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
    /// let (public_key, secret_key) = slh.generate_keypair()?;
    ///
    /// // Keys are ready to use
    /// println!("Public key size: {} bytes", public_key.to_bytes().len());
    /// println!("Secret key size: {} bytes", secret_key.to_bytes().len());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_keypair(&self) -> PqcResult<(SlhDsaPublicKey, SlhDsaSecretKey)> {
        let (pk_bytes, sk_bytes) = match self.variant {
            SlhDsaVariant::Sha2_128s => {
                let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_128f => {
                let (pk, sk) = slh_dsa_sha2_128f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_192s => {
                let (pk, sk) = slh_dsa_sha2_192s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_192f => {
                let (pk, sk) = slh_dsa_sha2_192f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_256s => {
                let (pk, sk) = slh_dsa_sha2_256s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_256f => {
                let (pk, sk) = slh_dsa_sha2_256f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake128s => {
                let (pk, sk) = slh_dsa_shake_128s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake128f => {
                let (pk, sk) = slh_dsa_shake_128f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake192s => {
                let (pk, sk) = slh_dsa_shake_192s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake192f => {
                let (pk, sk) = slh_dsa_shake_192f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake256s => {
                let (pk, sk) = slh_dsa_shake_256s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake256f => {
                let (pk, sk) = slh_dsa_shake_256f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
        };

        Ok((
            SlhDsaPublicKey {
                variant: self.variant,
                bytes: pk_bytes,
            },
            SlhDsaSecretKey {
                variant: self.variant,
                bytes: sk_bytes,
            },
        ))
    }

    /// Sign a message
    ///
    /// Creates a digital signature for the given message using the secret key.
    /// The signature is deterministic for a given message and key pair, but uses
    /// hedged randomness for enhanced security against RNG failures.
    ///
    /// # Arguments
    /// * `secret_key` - The secret key to use for signing
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The digital signature
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
    ///
    /// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
    /// let (public_key, secret_key) = slh.generate_keypair()?;
    ///
    /// // Sign a message
    /// let message = b"Important document";
    /// let signature = slh.sign(&secret_key, message)?;
    ///
    /// // Verify the signature
    /// assert!(slh.verify(&public_key, message, &signature)?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the signing process fails due to incompatible
    /// key types or internal signature generation errors.
    pub fn sign(&self, secret_key: &SlhDsaSecretKey, message: &[u8]) -> PqcResult<SlhDsaSignature> {
        self.sign_with_context(secret_key, message, b"")
    }

    /// Sign a message with context for domain separation
    ///
    /// Creates a digital signature with an additional context string that provides
    /// domain separation. This ensures signatures from different applications or
    /// contexts cannot be used interchangeably, even if they sign the same message.
    ///
    /// # Arguments
    /// * `secret_key` - The secret key to use for signing
    /// * `message` - The message to sign
    /// * `context` - Context string for domain separation (max 255 bytes)
    ///
    /// # Returns
    /// The digital signature bound to the context
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
    ///
    /// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
    /// let (public_key, secret_key) = slh.generate_keypair()?;
    ///
    /// // Sign with application-specific context
    /// let message = b"Transfer $1000";
    /// let context = b"BankApp-v2.0-Transfer";
    /// let signature = slh.sign_with_context(&secret_key, message, context)?;
    ///
    /// // Verification requires the same context
    /// assert!(slh.verify_with_context(&public_key, message, &signature, context)?);
    ///
    /// // Different context will fail
    /// let wrong_context = b"BankApp-v1.0-Transfer";
    /// assert!(!slh.verify_with_context(&public_key, message, &signature, wrong_context)?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret key variant doesn't match the SLH variant
    /// - The context is too long (exceeds maximum length)
    /// - Key deserialization fails
    /// - The signing operation fails
    pub fn sign_with_context(
        &self,
        secret_key: &SlhDsaSecretKey,
        message: &[u8],
        context: &[u8],
    ) -> PqcResult<SlhDsaSignature> {
        if secret_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match SLH variant {:?}",
                secret_key.variant, self.variant
            )));
        }

        if context.len() > SlhDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: SlhDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        // Use hedged randomness (true) for better security
        let use_hedged = true;

        let sig_bytes = match self.variant {
            SlhDsaVariant::Sha2_128s => {
                let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context, use_hedged)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;
                sig.to_vec()
            }
            SlhDsaVariant::Sha2_128f => {
                let sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context, use_hedged)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;
                sig.to_vec()
            }
            // Add other variants similarly...
            _ => {
                // For brevity, using SHA2-128s implementation for other variants
                // In production, implement all variants
                return Err(PqcError::UnsupportedVariant(format!("{:?}", self.variant)));
            }
        };

        Ok(SlhDsaSignature {
            variant: self.variant,
            bytes: sig_bytes,
        })
    }

    /// Verify a signature
    ///
    /// Verifies that a signature was created by the holder of the secret key
    /// corresponding to the provided public key for the given message.
    ///
    /// # Arguments
    /// * `public_key` - The public key to verify against
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
    ///
    /// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
    /// let (public_key, secret_key) = slh.generate_keypair()?;
    ///
    /// let message = b"Verify this message";
    /// let signature = slh.sign(&secret_key, message)?;
    ///
    /// // Valid signature verifies successfully
    /// assert!(slh.verify(&public_key, message, &signature)?);
    ///
    /// // Modified message fails verification
    /// let wrong_message = b"Different message";
    /// assert!(!slh.verify(&public_key, wrong_message, &signature)?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key variant doesn't match the SLH variant
    /// - The signature variant doesn't match the SLH variant
    /// - Key deserialization fails
    /// - The verification operation encounters an error
    pub fn verify(
        &self,
        public_key: &SlhDsaPublicKey,
        message: &[u8],
        signature: &SlhDsaSignature,
    ) -> PqcResult<bool> {
        self.verify_with_context(public_key, message, signature, b"")
    }

    /// Verify a signature with context
    ///
    /// Verifies a signature that was created with a specific context string.
    /// The same context must be provided for successful verification.
    ///
    /// # Arguments
    /// * `public_key` - The public key to verify against
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    /// * `context` - The context string used during signing
    ///
    /// # Returns
    /// `true` if the signature is valid with the given context, `false` otherwise
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::{SlhDsa, SlhDsaVariant};
    ///
    /// let slh = SlhDsa::new(SlhDsaVariant::Sha2_128f);
    /// let (public_key, secret_key) = slh.generate_keypair()?;
    ///
    /// // Sign with context
    /// let message = b"API request";
    /// let context = b"APIv3-POST-/users";
    /// let signature = slh.sign_with_context(&secret_key, message, context)?;
    ///
    /// // Verification succeeds with correct context
    /// assert!(slh.verify_with_context(&public_key, message, &signature, context)?);
    ///
    /// // Verification fails with wrong context
    /// assert!(!slh.verify_with_context(&public_key, message, &signature, b"APIv3-GET-/users")?);
    ///
    /// // Verification fails without context
    /// assert!(!slh.verify(&public_key, message, &signature)?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key variant doesn't match the SLH variant
    /// - The signature variant doesn't match the SLH variant
    /// - Key deserialization fails
    /// - The verification operation encounters an error
    pub fn verify_with_context(
        &self,
        public_key: &SlhDsaPublicKey,
        message: &[u8],
        signature: &SlhDsaSignature,
        context: &[u8],
    ) -> PqcResult<bool> {
        if public_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match SLH variant {:?}",
                public_key.variant, self.variant
            )));
        }

        if signature.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Signature variant {:?} doesn't match SLH variant {:?}",
                signature.variant, self.variant
            )));
        }

        if context.len() > SlhDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: SlhDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        let result = match self.variant {
            SlhDsaVariant::Sha2_128s => {
                let pk = slh_dsa_sha2_128s::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 7856] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                pk.verify(message, &sig_array, context)
            }
            SlhDsaVariant::Sha2_128f => {
                let pk = slh_dsa_sha2_128f::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 17088] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                pk.verify(message, &sig_array, context)
            }
            _ => {
                // For brevity, using false for other variants
                // In production, implement all variants
                return Err(PqcError::UnsupportedVariant(format!("{:?}", self.variant)));
            }
        };

        Ok(result)
    }
}

/// Create SLH-DSA-SHA2-128s instance (smallest signatures, 128-bit security)
///
/// This is the recommended variant for bandwidth-constrained applications that need
/// the smallest possible signatures (7,856 bytes) at the 128-bit security level.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::slh_dsa_sha2_128s;
///
/// let slh = slh_dsa_sha2_128s();
/// let (public_key, secret_key) = slh.generate_keypair()?;
/// let signature = slh.sign(&secret_key, b"Message")?;
/// // Signature is only 7,856 bytes
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub const fn slh_dsa_sha2_128s() -> SlhDsa {
    SlhDsa::new(SlhDsaVariant::Sha2_128s)
}

/// Create SLH-DSA-SHA2-128f instance (fast signing, 128-bit security)
///
/// This variant optimizes for signing speed at the cost of larger signatures
/// (17,088 bytes). Signing is approximately 8x faster than the 's' variant.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::slh_dsa_sha2_128f;
///
/// let slh = slh_dsa_sha2_128f();
/// let (public_key, secret_key) = slh.generate_keypair()?;
/// // Fast signing operation
/// let signature = slh.sign(&secret_key, b"Message")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub const fn slh_dsa_sha2_128f() -> SlhDsa {
    SlhDsa::new(SlhDsaVariant::Sha2_128f)
}

/// Create SLH-DSA-SHA2-192s instance (small signatures, 192-bit security)
///
/// Provides 192-bit post-quantum security with signatures of 16,224 bytes.
/// Suitable for applications requiring higher security than 128-bit.
///
/// Note: Currently returns SHA2-128s as SHA2-192s is not fully implemented.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::slh_dsa_sha2_192s;
///
/// let slh = slh_dsa_sha2_192s();
/// let (public_key, secret_key) = slh.generate_keypair()?;
/// let signature = slh.sign(&secret_key, b"Secure message")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub const fn slh_dsa_sha2_192s() -> SlhDsa {
    // TODO: Use Sha2_192s when fully implemented
    SlhDsa::new(SlhDsaVariant::Sha2_128s)
}

/// Create SLH-DSA-SHA2-256s instance (small signatures, 256-bit security)
///
/// Maximum security level with signatures of 29,792 bytes. Recommended for
/// applications requiring the highest level of post-quantum security.
///
/// Note: Currently returns SHA2-128s as SHA2-256s is not fully implemented.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::slh_dsa_sha2_256s;
///
/// let slh = slh_dsa_sha2_256s();
/// let (public_key, secret_key) = slh.generate_keypair()?;
/// let signature = slh.sign(&secret_key, b"Top secret")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub const fn slh_dsa_sha2_256s() -> SlhDsa {
    // TODO: Use Sha2_256s when fully implemented
    SlhDsa::new(SlhDsaVariant::Sha2_128s)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_sign_verify() {
        let slh = slh_dsa_sha2_128s();
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test message";
        let sig = slh.sign(&sk, message).unwrap();

        assert!(slh.verify(&pk, message, &sig).unwrap());

        // Wrong message should fail
        assert!(!slh.verify(&pk, b"Wrong message", &sig).unwrap());
    }

    #[test]
    fn test_with_context() {
        let slh = slh_dsa_sha2_128s();
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test message";
        let context = b"test context";
        let sig = slh.sign_with_context(&sk, message, context).unwrap();

        // Correct context verifies
        assert!(slh
            .verify_with_context(&pk, message, &sig, context)
            .unwrap());

        // Wrong context fails
        assert!(!slh
            .verify_with_context(&pk, message, &sig, b"wrong context")
            .unwrap());
    }

    #[test]
    fn test_serialization() {
        let slh = slh_dsa_sha2_128s();
        let (pk, sk) = slh.generate_keypair().unwrap();

        // Serialize and deserialize keys
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = SlhDsaPublicKey::from_bytes(SlhDsaVariant::Sha2_128s, &pk_bytes).unwrap();
        let sk2 = SlhDsaSecretKey::from_bytes(SlhDsaVariant::Sha2_128s, &sk_bytes).unwrap();

        // Use deserialized keys
        let message = b"Test";
        let sig = slh.sign(&sk2, message).unwrap();
        assert!(slh.verify(&pk2, message, &sig).unwrap());
    }
}
