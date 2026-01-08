// Rust 1.92+ raises unused_assignments on struct fields read via getter methods
// when used with derive macros like Zeroize. This is a known false positive.
#![allow(unused_assignments)]

//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) API
//!
//! Provides a simple interface to FIPS 204 ML-DSA for quantum-resistant digital signatures
//! without requiring users to manage RNG or internal details.
//!
//! # Examples
//!
//! ## Basic Signature and Verification
//! ```rust,no_run
//! use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaVariant};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create ML-DSA instance with 192-bit security
//! let dsa = ml_dsa_65();
//!
//! // Generate a signing keypair
//! let (public_key, secret_key) = dsa.generate_keypair()?;
//!
//! // Sign a message
//! let message = b"Important document to sign";
//! let signature = dsa.sign(&secret_key, message)?;
//!
//! // Verify the signature
//! let is_valid = dsa.verify(&public_key, message, &signature)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Document Signing with Context
//! ```rust,no_run
//! use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dsa = MlDsa::new(MlDsaVariant::MlDsa87); // Maximum security
//! let (public_key, secret_key) = dsa.generate_keypair()?;
//!
//! // Sign with additional context for domain separation
//! let document = b"Contract #12345";
//! let context = b"legal-documents-v1";
//! let signature = dsa.sign_with_context(&secret_key, document, context)?;
//!
//! // Verify with the same context
//! let valid = dsa.verify_with_context(&public_key, document, &signature, context)?;
//! assert!(valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Levels
//! - ML-DSA-44: NIST Level 2 (~128-bit classical, ~90-bit quantum)
//! - ML-DSA-65: NIST Level 3 (~192-bit classical, ~128-bit quantum)
//! - ML-DSA-87: NIST Level 5 (~256-bit classical, ~170-bit quantum)

use super::errors::{PqcError, PqcResult};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import FIPS implementations
use fips204::traits::{SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

/// ML-DSA algorithm variants
///
/// Selects the security level and performance characteristics for ML-DSA operations.
/// Higher security levels provide more protection but require larger keys and signatures.
///
/// # Examples
/// ```rust,no_run
/// use saorsa_pqc::api::sig::MlDsaVariant;
///
/// // Choose based on security requirements
/// let standard = MlDsaVariant::MlDsa65;     // Recommended for most uses
/// let lightweight = MlDsaVariant::MlDsa44;  // For constrained environments
/// let maximum = MlDsaVariant::MlDsa87;      // For highest security needs
///
/// println!("Public key size: {} bytes", standard.public_key_size());
/// println!("Signature size: {} bytes", standard.signature_size());
/// println!("Security: {}", standard.security_level());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    /// ML-DSA-44: NIST Level 2 security (~128-bit classical)
    /// - Public key: 1312 bytes
    /// - Secret key: 2560 bytes
    /// - Signature: 2420 bytes
    MlDsa44,
    /// ML-DSA-65: NIST Level 3 security (~192-bit classical) [RECOMMENDED]
    /// - Public key: 1952 bytes
    /// - Secret key: 4032 bytes
    /// - Signature: 3309 bytes
    MlDsa65,
    /// ML-DSA-87: NIST Level 5 security (~256-bit classical)
    /// - Public key: 2592 bytes
    /// - Secret key: 4896 bytes
    /// - Signature: 4627 bytes
    MlDsa87,
}

// Manual implementation of Zeroize for MlDsaVariant (no-op since it contains no sensitive data)
impl zeroize::Zeroize for MlDsaVariant {
    fn zeroize(&mut self) {
        // No sensitive data to zeroize in an enum variant selector
    }
}

impl MlDsaVariant {
    /// Get the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Get the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Get the signature size in bytes
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Get the security level description
    #[must_use]
    pub const fn security_level(&self) -> &'static str {
        match self {
            Self::MlDsa44 => "NIST Level 2 (~128-bit)",
            Self::MlDsa65 => "NIST Level 3 (~192-bit)",
            Self::MlDsa87 => "NIST Level 5 (~256-bit)",
        }
    }

    /// Maximum context length (255 bytes for all variants)
    pub const MAX_CONTEXT_LENGTH: usize = 255;
}

/// ML-DSA public key
///
/// Contains the public verification key for ML-DSA signatures.
/// This key can be freely shared and is used to verify signatures.
///
/// # Examples
/// ```rust,no_run
/// use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dsa = ml_dsa_65();
/// let (public_key, _) = dsa.generate_keypair()?;
///
/// // Export for distribution
/// let key_bytes = public_key.to_bytes();
/// println!("Public key size: {} bytes", key_bytes.len());
///
/// // Import from bytes
/// let imported = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &key_bytes)?;
/// assert_eq!(public_key.variant(), imported.variant());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaPublicKey {
    #[zeroize(skip)]
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Get the variant of this key
    #[must_use]
    pub const fn variant(&self) -> MlDsaVariant {
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
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.public_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.public_key_size(),
                got: bytes.len(),
            });
        }

        // Validate by trying to deserialize
        match variant {
            MlDsaVariant::MlDsa44 => {
                let _ = ml_dsa_44::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa65 => {
                let _ = ml_dsa_65::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa87 => {
                let _ = ml_dsa_87::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-DSA secret key
///
/// Contains the private signing key for ML-DSA signatures.
/// This key must be kept secret and is automatically zeroized when dropped.
///
/// # Security Considerations
/// - Never expose secret keys in logs or error messages
/// - Store securely (encrypted at rest)
/// - Use secure channels for transmission
/// - Consider hardware security modules (HSMs) for production
///
/// # Examples
/// ```rust,no_run
/// use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaSecretKey, MlDsaVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dsa = ml_dsa_65();
/// let (_, secret_key) = dsa.generate_keypair()?;
///
/// // Serialize for secure storage
/// let key_bytes = secret_key.to_bytes();
/// // Store key_bytes securely (encrypted)
///
/// // Later, restore from secure storage
/// let restored = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &key_bytes)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey {
    #[zeroize(skip)]
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaSecretKey {
    /// Get the variant of this key
    #[must_use]
    pub const fn variant(&self) -> MlDsaVariant {
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
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.secret_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.secret_key_size(),
                got: bytes.len(),
            });
        }

        // Validate by trying to deserialize
        match variant {
            MlDsaVariant::MlDsa44 => {
                let _ = ml_dsa_44::PrivateKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa65 => {
                let _ = ml_dsa_65::PrivateKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa87 => {
                let _ = ml_dsa_87::PrivateKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-DSA signature
///
/// A quantum-resistant digital signature produced by ML-DSA.
/// Signatures are non-deterministic (include randomness) for enhanced security.
///
/// # Size Requirements
/// - ML-DSA-44: 2420 bytes
/// - ML-DSA-65: 3309 bytes
/// - ML-DSA-87: 4627 bytes
///
/// # Examples
/// ```rust,no_run
/// use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaSignature, MlDsaVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dsa = ml_dsa_65();
/// let (public_key, secret_key) = dsa.generate_keypair()?;
///
/// // Create signature
/// let message = b"Document to sign";
/// let signature = dsa.sign(&secret_key, message)?;
///
/// // Serialize for transmission
/// let sig_bytes = signature.to_bytes();
/// assert_eq!(sig_bytes.len(), 3309); // ML-DSA-65 signature size
///
/// // Deserialize received signature
/// let received_sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)?;
///
/// // Verify
/// assert!(dsa.verify(&public_key, message, &received_sig)?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSignature {
    #[zeroize(skip)]
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    /// Get the variant of this signature
    #[must_use]
    pub const fn variant(&self) -> MlDsaVariant {
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
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
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

/// ML-DSA main API
///
/// The main interface for ML-DSA digital signature operations.
/// This struct provides methods for key generation, signing, and verification
/// according to NIST FIPS 204 standard.
///
/// # Examples
///
/// ## Basic Usage
/// ```rust,no_run
/// use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create instance with chosen security level
/// let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
///
/// // Generate keys
/// let (public_key, secret_key) = dsa.generate_keypair()?;
///
/// // Sign and verify
/// let message = b"Important message";
/// let signature = dsa.sign(&secret_key, message)?;
/// assert!(dsa.verify(&public_key, message, &signature)?);
/// # Ok(())
/// # }
/// ```
///
/// ## With Context for Domain Separation
/// ```rust,no_run
/// use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dsa = MlDsa::new(MlDsaVariant::MlDsa87);
/// let (public_key, secret_key) = dsa.generate_keypair()?;
///
/// // Use context to prevent cross-protocol attacks
/// let message = b"Transaction #42";
/// let context = b"blockchain-v2";
///
/// let signature = dsa.sign_with_context(&secret_key, message, context)?;
/// let valid = dsa.verify_with_context(&public_key, message, &signature, context)?;
/// assert!(valid);
///
/// // Different context will fail verification
/// let wrong_context = b"blockchain-v1";
/// let invalid = dsa.verify_with_context(&public_key, message, &signature, wrong_context)?;
/// assert!(!invalid);
/// # Ok(())
/// # }
/// ```
pub struct MlDsa {
    variant: MlDsaVariant,
}

impl MlDsa {
    /// Create a new ML-DSA instance with the specified variant
    ///
    /// # Arguments
    /// * `variant` - The ML-DSA parameter set to use (44, 65, or 87)
    ///
    /// # Example
    /// ```rust,no_run
    /// use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    ///
    /// let dsa_44 = MlDsa::new(MlDsaVariant::MlDsa44);   // NIST Level 2
    /// let dsa_65 = MlDsa::new(MlDsaVariant::MlDsa65);   // NIST Level 3
    /// let dsa_87 = MlDsa::new(MlDsaVariant::MlDsa87);   // NIST Level 5
    /// ```
    #[must_use]
    pub const fn new(variant: MlDsaVariant) -> Self {
        Self { variant }
    }

    /// Generate a new key pair
    ///
    /// Creates a new ML-DSA key pair using the system's secure random number generator.
    ///
    /// # Returns
    /// A tuple containing:
    /// - `MlDsaPublicKey`: The public key for signature verification
    /// - `MlDsaSecretKey`: The secret key for signing
    ///
    /// # Errors
    /// Returns an error if key generation fails (extremely rare with proper RNG).
    ///
    /// # Example
    /// ```rust,no_run
    /// use saorsa_pqc::api::sig::ml_dsa_65;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dsa = ml_dsa_65();
    /// let (public_key, secret_key) = dsa.generate_keypair()?;
    ///
    /// println!("Public key: {} bytes", public_key.to_bytes().len());
    /// println!("Secret key: {} bytes", secret_key.to_bytes().len());
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::large_stack_frames)]
    pub fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let (pk, sk) = ml_dsa_44::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlDsaPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlDsaSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlDsaVariant::MlDsa65 => {
                let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlDsaPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlDsaSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlDsaVariant::MlDsa87 => {
                let (pk, sk) = ml_dsa_87::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlDsaPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlDsaSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
        }
    }

    /// Sign a message
    ///
    /// Creates a digital signature for the given message using the secret key.
    /// The signature includes randomness for enhanced security against side-channel attacks.
    ///
    /// # Arguments
    /// * `secret_key` - The secret signing key
    /// * `message` - The message to sign (can be any length)
    ///
    /// # Returns
    /// A signature that can be verified with the corresponding public key
    ///
    /// # Errors
    /// - `InvalidInput`: If the secret key variant doesn't match
    /// - `SigningFailed`: If the signing operation fails
    ///
    /// # Example
    /// ```rust,no_run
    /// use saorsa_pqc::api::sig::ml_dsa_65;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dsa = ml_dsa_65();
    /// let (public_key, secret_key) = dsa.generate_keypair()?;
    ///
    /// // Sign any size message
    /// let message = b"This message can be any length";
    /// let signature = dsa.sign(&secret_key, message)?;
    ///
    /// // Verify the signature
    /// assert!(dsa.verify(&public_key, message, &signature)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        self.sign_with_context(secret_key, message, b"")
    }

    /// Sign a message with context
    ///
    /// Creates a signature with an additional context string for domain separation.
    /// This prevents signatures from being valid across different protocols or applications.
    ///
    /// # Arguments
    /// * `secret_key` - The secret signing key
    /// * `message` - The message to sign
    /// * `context` - Domain separation context (max 255 bytes)
    ///
    /// # Security Note
    /// Using context strings is recommended when the same keys are used in multiple
    /// protocols to prevent cross-protocol signature attacks.
    ///
    /// # Errors
    /// - `InvalidInput`: If the secret key variant doesn't match
    /// - `ContextTooLong`: If context exceeds 255 bytes
    /// - `SigningFailed`: If the signing operation fails
    ///
    /// # Example
    /// ```rust,no_run
    /// use saorsa_pqc::api::sig::ml_dsa_65;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dsa = ml_dsa_65();
    /// let (public_key, secret_key) = dsa.generate_keypair()?;
    ///
    /// // Sign with application-specific context
    /// let invoice = b"Invoice #2024-001";
    /// let context = b"accounting-system-v3";
    /// let signature = dsa.sign_with_context(&secret_key, invoice, context)?;
    ///
    /// // Must verify with same context
    /// assert!(dsa.verify_with_context(&public_key, invoice, &signature, context)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign_with_context(
        &self,
        secret_key: &MlDsaSecretKey,
        message: &[u8],
        context: &[u8],
    ) -> PqcResult<MlDsaSignature> {
        if secret_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match DSA variant {:?}",
                secret_key.variant, self.variant
            )));
        }

        if context.len() > MlDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: MlDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let sk = ml_dsa_44::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

                Ok(MlDsaSignature {
                    variant: self.variant,
                    bytes: sig.to_vec(),
                })
            }
            MlDsaVariant::MlDsa65 => {
                let sk = ml_dsa_65::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

                Ok(MlDsaSignature {
                    variant: self.variant,
                    bytes: sig.to_vec(),
                })
            }
            MlDsaVariant::MlDsa87 => {
                let sk = ml_dsa_87::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

                Ok(MlDsaSignature {
                    variant: self.variant,
                    bytes: sig.to_vec(),
                })
            }
        }
    }

    /// Verify a signature
    ///
    /// Verifies that a signature was created by the holder of the secret key
    /// corresponding to the provided public key.
    ///
    /// # Arguments
    /// * `public_key` - The public verification key
    /// * `message` - The original message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// - `Ok(true)` if the signature is valid
    /// - `Ok(false)` if the signature is invalid
    /// - `Err(_)` if verification cannot be performed (wrong key type, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the signature verification process fails due to
    /// incompatible key types or internal verification errors.
    ///
    /// # Example
    /// ```rust,no_run
    /// use saorsa_pqc::api::sig::ml_dsa_65;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dsa = ml_dsa_65();
    /// let (public_key, secret_key) = dsa.generate_keypair()?;
    ///
    /// let message = b"Authenticate this";
    /// let signature = dsa.sign(&secret_key, message)?;
    ///
    /// // Valid signature
    /// assert!(dsa.verify(&public_key, message, &signature)?);
    ///
    /// // Modified message fails
    /// let wrong_message = b"Authenticate that";
    /// assert!(!dsa.verify(&public_key, wrong_message, &signature)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        self.verify_with_context(public_key, message, signature, b"")
    }

    /// Verify a signature with context
    ///
    /// Verifies a signature that was created with a context string.
    /// The same context must be provided for successful verification.
    ///
    /// # Arguments
    /// * `public_key` - The public verification key
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    /// * `context` - The context string used during signing
    ///
    /// # Returns
    /// - `Ok(true)` if the signature is valid with the given context
    /// - `Ok(false)` if the signature is invalid or context doesn't match
    /// - `Err(_)` if verification cannot be performed
    ///
    /// # Errors
    ///
    /// Returns an error if the signature verification process fails due to
    /// incompatible key types, invalid context, or internal verification errors.
    ///
    /// # Example
    /// ```rust,no_run
    /// use saorsa_pqc::api::sig::ml_dsa_65;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dsa = ml_dsa_65();
    /// let (public_key, secret_key) = dsa.generate_keypair()?;
    ///
    /// let message = b"Protocol message";
    /// let context = b"protocol-v1";
    /// let signature = dsa.sign_with_context(&secret_key, message, context)?;
    ///
    /// // Correct context succeeds
    /// assert!(dsa.verify_with_context(&public_key, message, &signature, context)?);
    ///
    /// // Wrong context fails
    /// let wrong_context = b"protocol-v2";
    /// assert!(!dsa.verify_with_context(&public_key, message, &signature, wrong_context)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_with_context(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
        context: &[u8],
    ) -> PqcResult<bool> {
        if public_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match DSA variant {:?}",
                public_key.variant, self.variant
            )));
        }

        if signature.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Signature variant {:?} doesn't match DSA variant {:?}",
                signature.variant, self.variant
            )));
        }

        if context.len() > MlDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: MlDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let pk = ml_dsa_44::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 2420] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                Ok(pk.verify(message, &sig_array, context))
            }
            MlDsaVariant::MlDsa65 => {
                let pk = ml_dsa_65::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 3309] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                Ok(pk.verify(message, &sig_array, context))
            }
            MlDsaVariant::MlDsa87 => {
                let pk = ml_dsa_87::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 4627] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                Ok(pk.verify(message, &sig_array, context))
            }
        }
    }
}

/// Convenience function to create ML-DSA-65 (recommended default)
///
/// ML-DSA-65 provides NIST Level 3 security (~192-bit classical security),
/// which is suitable for most applications and offers a good balance
/// between security and performance.
///
/// # Why ML-DSA-65?
/// - Quantum resistance equivalent to 128-bit quantum security
/// - Moderate key and signature sizes
/// - Good performance on modern hardware
/// - Recommended by NIST for general use
///
/// # Example
/// ```rust,no_run
/// use saorsa_pqc::api::sig::ml_dsa_65;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Quick setup with recommended parameters
/// let dsa = ml_dsa_65();
///
/// // Use just like any MlDsa instance
/// let (public_key, secret_key) = dsa.generate_keypair()?;
/// let message = b"Sign this";
/// let signature = dsa.sign(&secret_key, message)?;
/// assert!(dsa.verify(&public_key, message, &signature)?);
/// # Ok(())
/// # }
/// ```
///
/// For other security levels, use:
/// - `MlDsa::new(MlDsaVariant::MlDsa44)` for NIST Level 2 (128-bit classical)
/// - `MlDsa::new(MlDsaVariant::MlDsa87)` for NIST Level 5 (256-bit classical)
#[must_use]
pub const fn ml_dsa_65() -> MlDsa {
    MlDsa::new(MlDsaVariant::MlDsa65)
}

/// Convenience function to create ML-DSA-44 (lightweight option)
///
/// ML-DSA-44 provides NIST Level 2 security (~128-bit classical security),
/// suitable for applications with strict size or performance constraints.
///
/// # Example
/// ```rust,no_run
/// use saorsa_pqc::api::sig::ml_dsa_44;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dsa = ml_dsa_44();
/// let (public_key, secret_key) = dsa.generate_keypair()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub const fn ml_dsa_44() -> MlDsa {
    MlDsa::new(MlDsaVariant::MlDsa44)
}

/// Convenience function to create ML-DSA-87 (maximum security)
///
/// ML-DSA-87 provides NIST Level 5 security (~256-bit classical security),
/// suitable for applications requiring the highest level of security.
///
/// # Example
/// ```rust,no_run
/// use saorsa_pqc::api::sig::ml_dsa_87;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dsa = ml_dsa_87();
/// let (public_key, secret_key) = dsa.generate_keypair()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub const fn ml_dsa_87() -> MlDsa {
    MlDsa::new(MlDsaVariant::MlDsa87)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message";
        let sig = dsa.sign(&sk, message).unwrap();

        assert!(dsa.verify(&pk, message, &sig).unwrap());

        // Wrong message should fail
        assert!(!dsa.verify(&pk, b"Wrong message", &sig).unwrap());
    }

    #[test]
    fn test_all_variants() {
        for variant in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let dsa = MlDsa::new(variant);
            let (pk, sk) = dsa.generate_keypair().unwrap();

            let message = b"Test message for all variants";
            let sig = dsa.sign(&sk, message).unwrap();

            assert!(dsa.verify(&pk, message, &sig).unwrap());
        }
    }

    #[test]
    fn test_with_context() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message";
        let context = b"test context";
        let sig = dsa.sign_with_context(&sk, message, context).unwrap();

        // Correct context verifies
        assert!(dsa
            .verify_with_context(&pk, message, &sig, context)
            .unwrap());

        // Wrong context fails
        assert!(!dsa
            .verify_with_context(&pk, message, &sig, b"wrong context")
            .unwrap());
    }

    #[test]
    fn test_serialization() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        // Serialize and deserialize keys
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes).unwrap();
        let sk2 = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes).unwrap();

        // Use deserialized keys
        let message = b"Test";
        let sig = dsa.sign(&sk2, message).unwrap();
        assert!(dsa.verify(&pk2, message, &sig).unwrap());
    }

    #[test]
    fn test_context_too_long() {
        let dsa = ml_dsa_65();
        let (_, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test";
        let long_context = vec![0u8; 256]; // Too long

        let result = dsa.sign_with_context(&sk, message, &long_context);
        assert!(matches!(result, Err(PqcError::ContextTooLong { .. })));
    }
}
