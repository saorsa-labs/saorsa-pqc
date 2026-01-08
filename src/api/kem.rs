// Rust 1.92+ raises unused_assignments on struct fields read via getter methods
// when used with derive macros like Zeroize. This is a known false positive.
#![allow(unused_assignments)]

//! ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) API
//!
//! Provides a simple interface to FIPS 203 ML-KEM without requiring
//! users to manage RNG or internal details.
//!
//! # Examples
//!
//! ## Basic Key Encapsulation
//! ```rust
//! use saorsa_pqc::api::kem::{ml_kem_768, MlKemVariant};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create ML-KEM instance with 192-bit security
//! let kem = ml_kem_768();
//!
//! // Generate a keypair
//! let (public_key, secret_key) = kem.generate_keypair()?;
//!
//! // Encapsulate a shared secret
//! let (shared_secret_enc, ciphertext) = kem.encapsulate(&public_key)?;
//!
//! // Decapsulate to recover the shared secret
//! let shared_secret_dec = kem.decapsulate(&secret_key, &ciphertext)?;
//!
//! // Verify the shared secrets match
//! assert_eq!(shared_secret_enc.to_bytes(), shared_secret_dec.to_bytes());
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Serialization
//! ```rust
//! use saorsa_pqc::api::kem::{ml_kem_768, MlKemPublicKey, MlKemVariant};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let kem = ml_kem_768();
//! let (public_key, _) = kem.generate_keypair()?;
//!
//! // Export public key to bytes
//! let key_bytes = public_key.to_bytes();
//!
//! // Import public key from bytes
//! let imported = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &key_bytes)?;
//! assert_eq!(public_key.to_bytes(), imported.to_bytes());
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Levels
//! - ML-KEM-512: NIST Level 1 (128-bit quantum security)
//! - ML-KEM-768: NIST Level 3 (192-bit quantum security)
//! - ML-KEM-1024: NIST Level 5 (256-bit quantum security)

use super::errors::{PqcError, PqcResult};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import FIPS implementations
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};

/// ML-KEM algorithm variants
///
/// # Examples
/// ```rust
/// use saorsa_pqc::api::kem::MlKemVariant;
///
/// let variant = MlKemVariant::MlKem768;
/// println!("Security: {}", variant.security_level());
/// println!("Public key size: {} bytes", variant.public_key_size());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    /// ML-KEM-512: NIST Level 1 security (128-bit)
    MlKem512,
    /// ML-KEM-768: NIST Level 3 security (192-bit)
    MlKem768,
    /// ML-KEM-1024: NIST Level 5 security (256-bit)
    MlKem1024,
}

// Manual implementation of Zeroize for MlKemVariant (no-op since it contains no sensitive data)
impl zeroize::Zeroize for MlKemVariant {
    fn zeroize(&mut self) {
        // No sensitive data to zeroize in an enum variant selector
    }
}

impl MlKemVariant {
    /// Get the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Get the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Get the ciphertext size in bytes
    #[must_use]
    pub const fn ciphertext_size(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Get the shared secret size in bytes (always 32)
    #[must_use]
    pub const fn shared_secret_size(&self) -> usize {
        32
    }

    /// Get the security level description
    #[must_use]
    pub const fn security_level(&self) -> &'static str {
        match self {
            Self::MlKem512 => "NIST Level 1 (128-bit)",
            Self::MlKem768 => "NIST Level 3 (192-bit)",
            Self::MlKem1024 => "NIST Level 5 (256-bit)",
        }
    }
}

/// ML-KEM public key
///
/// This structure holds the public key material for ML-KEM operations.
/// The key is automatically zeroized when dropped to prevent sensitive data leakage.
///
/// # Examples
/// ```rust
/// use saorsa_pqc::api::kem::{ml_kem_768, MlKemPublicKey, MlKemVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = ml_kem_768();
/// let (public_key, _) = kem.generate_keypair()?;
///
/// // Check key properties
/// assert_eq!(public_key.variant(), MlKemVariant::MlKem768);
/// assert_eq!(public_key.to_bytes().len(), 1184);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemPublicKey {
    #[zeroize(skip)]
    variant: MlKemVariant,
    bytes: Vec<u8>,
}

impl MlKemPublicKey {
    /// Get the variant of this key
    #[must_use]
    pub const fn variant(&self) -> MlKemVariant {
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
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.public_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.public_key_size(),
                got: bytes.len(),
            });
        }

        // Validate by trying to deserialize
        match variant {
            MlKemVariant::MlKem512 => {
                let _ = ml_kem_512::EncapsKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem768 => {
                let _ = ml_kem_768::EncapsKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem1024 => {
                let _ = ml_kem_1024::EncapsKey::try_from_bytes(bytes.try_into().map_err(|_| {
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

/// ML-KEM secret key
///
/// Contains the secret key material for ML-KEM decapsulation operations.
/// This structure automatically zeroizes its contents when dropped to prevent
/// key material from remaining in memory.
///
/// # Security Considerations
/// - Always handle secret keys with care
/// - Never expose secret keys in logs or error messages
/// - Use secure channels when transmitting secret keys
/// - Consider using hardware security modules (HSMs) for key storage in production
///
/// # Examples
/// ```rust
/// use saorsa_pqc::api::kem::{ml_kem_768, MlKemSecretKey, MlKemVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = ml_kem_768();
/// let (_, secret_key) = kem.generate_keypair()?;
///
/// // Serialize for secure storage
/// let key_bytes = secret_key.to_bytes();
/// // Store key_bytes securely (e.g., encrypted file, HSM, key vault)
///
/// // Later, restore from secure storage
/// let restored = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &key_bytes)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey {
    #[zeroize(skip)]
    variant: MlKemVariant,
    bytes: Vec<u8>,
}

impl MlKemSecretKey {
    /// Get the variant of this key
    #[must_use]
    pub const fn variant(&self) -> MlKemVariant {
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
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.secret_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.secret_key_size(),
                got: bytes.len(),
            });
        }

        // Validate by trying to deserialize
        match variant {
            MlKemVariant::MlKem512 => {
                let _ = ml_kem_512::DecapsKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem768 => {
                let _ = ml_kem_768::DecapsKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem1024 => {
                let _ = ml_kem_1024::DecapsKey::try_from_bytes(bytes.try_into().map_err(|_| {
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

/// ML-KEM ciphertext
///
/// Represents an encapsulated ciphertext containing an encrypted shared secret.
/// The ciphertext is created during encapsulation and required for decapsulation.
///
/// # Size Requirements
/// - ML-KEM-512: 768 bytes
/// - ML-KEM-768: 1088 bytes
/// - ML-KEM-1024: 1568 bytes
///
/// # Examples
/// ```rust
/// use saorsa_pqc::api::kem::{ml_kem_768, MlKemCiphertext, MlKemVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = ml_kem_768();
/// let (public_key, secret_key) = kem.generate_keypair()?;
///
/// // Create ciphertext through encapsulation
/// let (shared_secret, ciphertext) = kem.encapsulate(&public_key)?;
///
/// // Serialize for transmission
/// let ct_bytes = ciphertext.to_bytes();
/// assert_eq!(ct_bytes.len(), 1088); // ML-KEM-768 ciphertext size
///
/// // Deserialize received ciphertext
/// let received_ct = MlKemCiphertext::from_bytes(MlKemVariant::MlKem768, &ct_bytes)?;
///
/// // Use for decapsulation
/// let recovered_secret = kem.decapsulate(&secret_key, &received_ct)?;
/// assert_eq!(shared_secret.to_bytes(), recovered_secret.to_bytes());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemCiphertext {
    #[zeroize(skip)]
    variant: MlKemVariant,
    bytes: Vec<u8>,
}

impl MlKemCiphertext {
    /// Get the variant of this ciphertext
    #[must_use]
    pub const fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Export the ciphertext as bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a ciphertext from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has an incorrect length for the specified variant.
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.ciphertext_size() {
            return Err(PqcError::InvalidCiphertextSize {
                expected: variant.ciphertext_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-KEM shared secret
///
/// A 256-bit (32-byte) shared secret established through key encapsulation.
/// This secret is identical for both parties after successful encapsulation
/// and decapsulation, and can be used as key material for symmetric encryption.
///
/// # Security Properties
/// - Always 32 bytes (256 bits) regardless of ML-KEM variant
/// - Cryptographically random and unpredictable
/// - Automatically zeroized when dropped from memory
/// - Safe for use as AES-256 key material or KDF input
///
/// # Examples
/// ```rust
/// use saorsa_pqc::api::kem::ml_kem_768;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = ml_kem_768();
/// let (public_key, secret_key) = kem.generate_keypair()?;
///
/// // Establish shared secret
/// let (shared_secret_enc, ciphertext) = kem.encapsulate(&public_key)?;
/// let shared_secret_dec = kem.decapsulate(&secret_key, &ciphertext)?;
///
/// // Both parties have the same secret
/// assert_eq!(shared_secret_enc.to_bytes(), shared_secret_dec.to_bytes());
///
/// // Use as symmetric key material
/// let key_material = shared_secret_enc.to_bytes();
/// // Can now use key_material for AES-256-GCM, ChaCha20-Poly1305, etc.
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret {
    bytes: [u8; 32],
}

impl MlKemSharedSecret {
    /// Get the shared secret as bytes
    ///
    /// Returns the 32-byte shared secret for use as key material.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Get a reference to the shared secret bytes
    ///
    /// This avoids copying the secret when only a reference is needed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from bytes (for testing)
    #[cfg(test)]
    #[allow(clippy::indexing_slicing)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

/// ML-KEM main API
///
/// The main interface for ML-KEM key encapsulation operations.
/// This struct provides methods for key generation, encapsulation, and decapsulation
/// according to NIST FIPS 203 standard.
///
/// # Examples
///
/// ## Complete Key Encapsulation Flow
/// ```rust
/// use saorsa_pqc::api::kem::{MlKem, MlKemVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Choose security level
/// let kem = MlKem::new(MlKemVariant::MlKem768);
///
/// // Alice generates a key pair
/// let (alice_public, alice_secret) = kem.generate_keypair()?;
///
/// // Bob encapsulates a shared secret using Alice's public key
/// let (bob_shared_secret, ciphertext) = kem.encapsulate(&alice_public)?;
///
/// // Alice decapsulates to get the same shared secret
/// let alice_shared_secret = kem.decapsulate(&alice_secret, &ciphertext)?;
///
/// // Both parties now have the same shared secret
/// assert_eq!(alice_shared_secret.to_bytes(), bob_shared_secret.to_bytes());
/// # Ok(())
/// # }
/// ```
///
/// ## Hybrid Encryption Example
/// ```rust
/// use saorsa_pqc::api::kem::{MlKem, MlKemVariant};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = MlKem::new(MlKemVariant::MlKem1024); // Highest security
///
/// // Generate recipient's keys
/// let (recipient_public, recipient_secret) = kem.generate_keypair()?;
///
/// // Sender: Encapsulate and derive encryption key
/// let (shared_secret, ciphertext) = kem.encapsulate(&recipient_public)?;
/// let encryption_key = shared_secret.to_bytes();
/// // Use encryption_key with AES-256-GCM to encrypt actual message
///
/// // Recipient: Decapsulate and derive same encryption key
/// let recovered_secret = kem.decapsulate(&recipient_secret, &ciphertext)?;
/// let decryption_key = recovered_secret.to_bytes();
/// // Use decryption_key to decrypt the message
///
/// assert_eq!(encryption_key, decryption_key);
/// # Ok(())
/// # }
/// ```
pub struct MlKem {
    variant: MlKemVariant,
}

impl MlKem {
    /// Create a new ML-KEM instance with the specified variant
    ///
    /// # Arguments
    /// * `variant` - The ML-KEM parameter set to use (512, 768, or 1024)
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::kem::{MlKem, MlKemVariant};
    ///
    /// let kem_512 = MlKem::new(MlKemVariant::MlKem512);   // NIST Level 1
    /// let kem_768 = MlKem::new(MlKemVariant::MlKem768);   // NIST Level 3
    /// let kem_1024 = MlKem::new(MlKemVariant::MlKem1024); // NIST Level 5
    /// ```
    #[must_use]
    pub const fn new(variant: MlKemVariant) -> Self {
        Self { variant }
    }

    /// Generate a new key pair
    ///
    /// Creates a new ML-KEM key pair using the system's secure random number generator.
    ///
    /// # Returns
    /// A tuple containing:
    /// - `MlKemPublicKey`: The public key for encapsulation
    /// - `MlKemSecretKey`: The secret key for decapsulation
    ///
    /// # Errors
    /// Returns an error if the key generation fails (extremely rare with proper RNG).
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::kem::ml_kem_768;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let kem = ml_kem_768();
    /// let (public_key, secret_key) = kem.generate_keypair()?;
    ///
    /// println!("Public key size: {} bytes", public_key.to_bytes().len());
    /// println!("Secret key size: {} bytes", secret_key.to_bytes().len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        match self.variant {
            MlKemVariant::MlKem512 => {
                let (pk, sk) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem768 => {
                let (pk, sk) = ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem1024 => {
                let (pk, sk) = ml_kem_1024::KG::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
        }
    }

    /// Generate a deterministic key pair from seed values
    ///
    /// This is primarily for testing with known test vectors.
    /// Takes two 32-byte seed values (d and z) as specified in FIPS 203.
    #[must_use]
    pub fn generate_keypair_from_seed(
        &self,
        d_seed: &[u8; 32],
        z_seed: &[u8; 32],
    ) -> (MlKemPublicKey, MlKemSecretKey) {
        match self.variant {
            MlKemVariant::MlKem512 => {
                let (pk, sk) = ml_kem_512::KG::keygen_from_seed(*d_seed, *z_seed);
                (
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                )
            }
            MlKemVariant::MlKem768 => {
                let (pk, sk) = ml_kem_768::KG::keygen_from_seed(*d_seed, *z_seed);
                (
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                )
            }
            MlKemVariant::MlKem1024 => {
                let (pk, sk) = ml_kem_1024::KG::keygen_from_seed(*d_seed, *z_seed);
                (
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                )
            }
        }
    }

    /// Encapsulate a shared secret using a public key
    ///
    /// Generates a shared secret and encapsulates it using the recipient's public key.
    /// This operation is performed by the sender who wants to establish a shared secret
    /// with the holder of the corresponding secret key.
    ///
    /// # Arguments
    /// * `public_key` - The recipient's public key
    ///
    /// # Returns
    /// A tuple containing:
    /// - `MlKemSharedSecret`: The shared secret (for the sender)
    /// - `MlKemCiphertext`: The ciphertext to send to the recipient
    ///
    /// # Errors
    /// - `InvalidInput`: If the public key variant doesn't match the KEM variant
    /// - `EncapsulationFailed`: If the encapsulation operation fails
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::kem::ml_kem_768;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let kem = ml_kem_768();
    /// let (recipient_public_key, _) = kem.generate_keypair()?;
    ///
    /// // Sender encapsulates a shared secret
    /// let (shared_secret, ciphertext) = kem.encapsulate(&recipient_public_key)?;
    ///
    /// // Send 'ciphertext' to the recipient
    /// // Use 'shared_secret' as encryption key
    /// # Ok(())
    /// # }
    /// ```
    pub fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemSharedSecret, MlKemCiphertext)> {
        if public_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match KEM variant {:?}",
                public_key.variant, self.variant
            )));
        }

        match self.variant {
            MlKemVariant::MlKem512 => {
                let ek = ml_kem_512::EncapsKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let (ss, ct) = ek
                    .try_encaps_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;

                Ok((
                    MlKemSharedSecret {
                        bytes: ss.into_bytes(),
                    },
                    MlKemCiphertext {
                        variant: self.variant,
                        bytes: ct.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem768 => {
                let ek = ml_kem_768::EncapsKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let (ss, ct) = ek
                    .try_encaps_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;

                Ok((
                    MlKemSharedSecret {
                        bytes: ss.into_bytes(),
                    },
                    MlKemCiphertext {
                        variant: self.variant,
                        bytes: ct.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem1024 => {
                let ek = ml_kem_1024::EncapsKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let (ss, ct) = ek
                    .try_encaps_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;

                Ok((
                    MlKemSharedSecret {
                        bytes: ss.into_bytes(),
                    },
                    MlKemCiphertext {
                        variant: self.variant,
                        bytes: ct.into_bytes().to_vec(),
                    },
                ))
            }
        }
    }

    /// Decapsulate a shared secret using a secret key
    ///
    /// Recovers the shared secret from a ciphertext using the recipient's secret key.
    /// This operation is performed by the recipient to obtain the same shared secret
    /// that the sender generated during encapsulation.
    ///
    /// # Security Note
    /// ML-KEM uses implicit rejection, meaning that even if the ciphertext is invalid
    /// or corrupted, the operation will still succeed but produce a different
    /// (deterministic) shared secret. This prevents timing attacks.
    ///
    /// # Arguments
    /// * `secret_key` - The recipient's secret key
    /// * `ciphertext` - The ciphertext received from the sender
    ///
    /// # Returns
    /// The shared secret that matches what the sender generated
    ///
    /// # Errors
    /// - `InvalidInput`: If key or ciphertext variants don't match the KEM variant
    /// - `DecapsulationFailed`: If the decapsulation operation fails
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::api::kem::ml_kem_768;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let kem = ml_kem_768();
    /// let (public_key, secret_key) = kem.generate_keypair()?;
    ///
    /// // Sender creates ciphertext
    /// let (sender_secret, ciphertext) = kem.encapsulate(&public_key)?;
    ///
    /// // Recipient recovers the same secret
    /// let recipient_secret = kem.decapsulate(&secret_key, &ciphertext)?;
    ///
    /// assert_eq!(sender_secret.to_bytes(), recipient_secret.to_bytes());
    /// # Ok(())
    /// # }
    /// ```
    pub fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<MlKemSharedSecret> {
        if secret_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match KEM variant {:?}",
                secret_key.variant, self.variant
            )));
        }

        if ciphertext.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Ciphertext variant {:?} doesn't match KEM variant {:?}",
                ciphertext.variant, self.variant
            )));
        }

        match self.variant {
            MlKemVariant::MlKem512 => {
                let dk = ml_kem_512::DecapsKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let ct = ml_kem_512::CipherText::try_from_bytes(
                    ciphertext.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidCiphertextSize {
                            expected: self.variant.ciphertext_size(),
                            got: ciphertext.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let ss = dk
                    .try_decaps(&ct)
                    .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;

                Ok(MlKemSharedSecret {
                    bytes: ss.into_bytes(),
                })
            }
            MlKemVariant::MlKem768 => {
                let dk = ml_kem_768::DecapsKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let ct = ml_kem_768::CipherText::try_from_bytes(
                    ciphertext.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidCiphertextSize {
                            expected: self.variant.ciphertext_size(),
                            got: ciphertext.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let ss = dk
                    .try_decaps(&ct)
                    .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;

                Ok(MlKemSharedSecret {
                    bytes: ss.into_bytes(),
                })
            }
            MlKemVariant::MlKem1024 => {
                let dk = ml_kem_1024::DecapsKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let ct = ml_kem_1024::CipherText::try_from_bytes(
                    ciphertext.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidCiphertextSize {
                            expected: self.variant.ciphertext_size(),
                            got: ciphertext.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let ss = dk
                    .try_decaps(&ct)
                    .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;

                Ok(MlKemSharedSecret {
                    bytes: ss.into_bytes(),
                })
            }
        }
    }
}

/// Convenience function to create ML-KEM-768 (recommended default)
///
/// ML-KEM-768 provides NIST Level 3 security (192-bit quantum security),
/// which is suitable for most applications and offers a good balance
/// between security and performance.
///
/// # Why ML-KEM-768?
/// - Quantum resistance equivalent to AES-192
/// - Moderate key and ciphertext sizes
/// - Good performance on modern hardware
/// - Recommended by NIST for general use
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::kem::ml_kem_768;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Quick setup with recommended parameters
/// let kem = ml_kem_768();
///
/// // Use just like any MlKem instance
/// let (public_key, secret_key) = kem.generate_keypair()?;
/// let (shared_secret, ciphertext) = kem.encapsulate(&public_key)?;
/// # Ok(())
/// # }
/// ```
///
/// For other security levels, use:
/// - `MlKem::new(MlKemVariant::MlKem512)` for NIST Level 1 (128-bit)
/// - `MlKem::new(MlKemVariant::MlKem1024)` for NIST Level 5 (256-bit)
#[must_use]
pub const fn ml_kem_768() -> MlKem {
    MlKem::new(MlKemVariant::MlKem768)
}

/// Convenience function to create ML-KEM-512 (lightweight option)
///
/// ML-KEM-512 provides NIST Level 1 security (128-bit quantum security),
/// suitable for applications with strict performance or bandwidth constraints.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::kem::ml_kem_512;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = ml_kem_512();
/// let (public_key, secret_key) = kem.generate_keypair()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub const fn ml_kem_512() -> MlKem {
    MlKem::new(MlKemVariant::MlKem512)
}

/// Convenience function to create ML-KEM-1024 (maximum security)
///
/// ML-KEM-1024 provides NIST Level 5 security (256-bit quantum security),
/// suitable for applications requiring the highest level of security.
///
/// # Example
/// ```rust
/// use saorsa_pqc::api::kem::ml_kem_1024;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kem = ml_kem_1024();
/// let (public_key, secret_key) = kem.generate_keypair()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub const fn ml_kem_1024() -> MlKem {
    MlKem::new(MlKemVariant::MlKem1024)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let kem = ml_kem_768();
        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    }

    #[test]
    fn test_all_variants() {
        for variant in [
            MlKemVariant::MlKem512,
            MlKemVariant::MlKem768,
            MlKemVariant::MlKem1024,
        ] {
            let kem = MlKem::new(variant);
            let (pk, sk) = kem.generate_keypair().unwrap();
            let (ss1, ct) = kem.encapsulate(&pk).unwrap();
            let ss2 = kem.decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss1.to_bytes(), ss2.to_bytes());
        }
    }

    #[test]
    #[allow(clippy::similar_names, clippy::unwrap_used)]
    fn test_serialization() {
        let kem = ml_kem_768();
        let (pk, sk) = kem.generate_keypair().unwrap();

        // Serialize and deserialize keys
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &pk_bytes).unwrap();
        let sk2 = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &sk_bytes).unwrap();

        // Use deserialized keys
        let (ss1, ct) = kem.encapsulate(&pk2).unwrap();
        let ss2 = kem.decapsulate(&sk2, &ct).unwrap();
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    }

    #[test]
    fn test_invalid_key_size() {
        let result = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &[0u8; 100]);
        assert!(matches!(result, Err(PqcError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_variant_mismatch() {
        let kem512 = MlKem::new(MlKemVariant::MlKem512);
        let kem768 = MlKem::new(MlKemVariant::MlKem768);

        let (pk768, _) = kem768.generate_keypair().unwrap();

        let result = kem512.encapsulate(&pk768);
        assert!(matches!(result, Err(PqcError::InvalidInput(_))));
    }
}
