//! # Saorsa Post-Quantum Cryptography Library
//!
//! A comprehensive, production-ready Post-Quantum Cryptography (PQC) library implementing
//! NIST-standardized algorithms FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA)
//! with both pure PQC and hybrid (classical + PQC) modes.
//!
//! ## Features
//!
//! ### Key Encapsulation Mechanisms (KEM) - FIPS 203
//! - **ML-KEM-512**: NIST Level 1 security (128-bit)
//! - **ML-KEM-768**: NIST Level 3 security (192-bit)
//! - **ML-KEM-1024**: NIST Level 5 security (256-bit)
//! - **Hybrid KEM**: Classical ECDH + ML-KEM for defense-in-depth
//!
//! ### Digital Signatures - FIPS 204
//! - **ML-DSA-44**: NIST Level 2 security (~128-bit)
//! - **ML-DSA-65**: NIST Level 3 security (~192-bit)
//! - **ML-DSA-87**: NIST Level 5 security (~256-bit)
//! - **Hybrid Signatures**: Classical Ed25519 + ML-DSA for defense-in-depth
//!
//! ### Hash-Based Signatures - FIPS 205
//! - **SLH-DSA**: 12 parameter sets (SHA2/SHAKE, 128/192/256-bit, fast/small)
//!
//! ### Symmetric Encryption (Quantum-Resistant)
//! - **ChaCha20-Poly1305**: AEAD cipher providing quantum-resistant symmetric encryption
//! - **Password-based Key Derivation**: PBKDF2 for secure key derivation from passwords
//! - **Authenticated Encryption**: Built-in authentication prevents tampering
//!
//! ### Network Protocol Support
//! - **Raw Public Keys**: Ed25519 key support for P2P authentication
//! - **Key Derivation**: Utilities for network identity derivation
//! - **Protocol Agnostic**: Designed for use with any network protocol
//!
//! ### Security Features
//! - **Memory Protection**: Secure memory handling and cleanup
//! - **Constant-Time Operations**: Resistance to side-channel attacks
//! - **Algorithm Negotiation**: Automatic algorithm selection and fallback
//! - **Security Validation**: Comprehensive parameter and key validation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use saorsa_pqc::pqc::{MlKem768, MlKemOperations, HybridPublicKeyEncryption};
//! use saorsa_pqc::symmetric::{SymmetricKey, ChaCha20Poly1305Cipher};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Key encapsulation with ML-KEM
//! let ml_kem = MlKem768::new();
//! let (pub_key, sec_key) = ml_kem.generate_keypair()?;
//! let (ciphertext, shared_secret) = ml_kem.encapsulate(&pub_key)?;
//! let recovered_secret = ml_kem.decapsulate(&sec_key, &ciphertext)?;
//! assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
//!
//! // Public key encryption
//! let pke = HybridPublicKeyEncryption::new();
//! let plaintext = b"Secret message";
//! let associated_data = b"context";
//! let encrypted = pke.encrypt(&pub_key, plaintext, associated_data)?;
//! let decrypted = pke.decrypt(&sec_key, &encrypted, associated_data)?;
//! assert_eq!(plaintext, &decrypted[..]);
//!
//! // Quantum-resistant symmetric encryption
//! let key = SymmetricKey::generate();
//! let cipher = ChaCha20Poly1305Cipher::new(&key);
//! let (ciphertext, nonce) = cipher.encrypt(b"Quantum-safe data", None)?;
//! let decrypted = cipher.decrypt(&ciphertext, &nonce, None)?;
//! assert_eq!(b"Quantum-safe data", &decrypted[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! This library is designed with security as the primary concern:
//!
//! - **No Panics**: All operations return `Result` types with proper error handling
//! - **Memory Safety**: Sensitive data is zeroed on drop and uses secure allocators
//! - **Timing Attacks**: Constant-time implementations where cryptographically relevant
//! - **Algorithm Agility**: Support for multiple algorithms and hybrid modes
//! - **Validation**: Comprehensive input validation and parameter checking
//!
//! ## Performance
//!
//! The library is optimized for both security and performance:
//!
//! - **FIPS-Compliant Implementations**: Uses FIPS 203/204/205 certified crates
//! - **Memory Pooling**: Reduces allocation overhead for frequent operations
//! - **Parallel Processing**: Optional multi-threading for batch operations
//! - **Zero-Copy**: Minimal data copying in critical paths
//!
//! ## Feature Flags
//!
//! The library is designed to work out-of-the-box with sensible defaults.
//! Optional features are available for specific use cases:
//!
//! - `simd`: Enable SIMD acceleration for performance (requires `wide` crate)
//! - `cert_compression`: Enable certificate compression optimization
//! - `dangerous_configuration`: Enable dangerous configuration options (not recommended)
//! - `test-utils`: Enable testing utilities
//! - `benchmarks`: Enable benchmarking support
//!
//! ## Safety and Compliance
//!
//! - **NIST Standards**: Implements FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)
//! - **No Unsafe Code**: Forbidden by lint configuration
//! - **Comprehensive Testing**: Property-based testing and fuzzing
//! - **Security Auditing**: Regular security audits and vulnerability scanning

#![deny(
    missing_docs,
    unsafe_code,
    unused_must_use,
    clippy::panic,
    clippy::unimplemented,
    clippy::todo
)]
#![warn(clippy::correctness, clippy::suspicious, clippy::perf)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Core PQC modules - the main attraction
pub mod pqc;

// Symmetric encryption (quantum-resistant)
pub mod symmetric;

// Comprehensive API module
pub mod api;

// Re-export the comprehensive API for easy access
pub use api::{
    // Utils
    init as api_init,
    kdf::helpers as kdf_helpers,
    // Convenience functions
    kem::ml_kem_768,
    sig::ml_dsa_65,
    slh::slh_dsa_sha2_128s,

    supported_algorithms,
    version as api_version,
    // KDF exports
    HkdfSha3_256,
    HkdfSha3_512,
    KdfAlgorithm,
    MlDsa,
    MlDsaPublicKey as ApiMlDsaPublicKey,
    MlDsaSecretKey as ApiMlDsaSecretKey,
    MlDsaSignature as ApiMlDsaSignature,
    MlDsaVariant,
    // Main APIs
    MlKem,
    MlKemCiphertext as ApiMlKemCiphertext,
    MlKemPublicKey as ApiMlKemPublicKey,
    MlKemSecretKey as ApiMlKemSecretKey,
    MlKemSharedSecret,
    MlKemVariant,
    // Error types
    PqcError as ApiError,
    PqcResult as ApiResult,

    SlhDsa,
    SlhDsaPublicKey,
    SlhDsaSecretKey,
    SlhDsaSignature,

    SlhDsaVariant,
};

// Re-export the most commonly used types and traits for convenience (legacy)
pub use pqc::{
    // Types
    types::{
        HybridKemCiphertext, HybridKemPublicKey, HybridKemSecretKey, HybridSignaturePublicKey,
        HybridSignatureSecretKey, HybridSignatureValue, MlDsaPublicKey, MlDsaSecretKey,
        MlDsaSignature, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, PqcError, PqcResult,
        SharedSecret,
    },
    EncryptedMessage,

    // Hybrid modes
    HybridKem,
    // Public key encryption
    HybridPublicKeyEncryption,
    HybridSignature,

    MlDsa65,
    MlDsaOperations,

    // Implementations
    MlKem768,
    // Core traits
    MlKemOperations,
};

// Re-export symmetric encryption for convenience
pub use symmetric::{
    ChaCha20Poly1305Cipher, EncryptedMessage as SymmetricEncryptedMessage, SymmetricError,
    SymmetricKey,
};

// Note: This is a pure PQC library - protocol integration is left to consuming crates

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-export FIPS implementations directly
pub use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768, traits as kem_traits};

pub use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87, traits as dsa_traits};

pub use fips205::{
    slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s, slh_dsa_sha2_256f,
    slh_dsa_sha2_256s, slh_dsa_shake_128f, slh_dsa_shake_128s, slh_dsa_shake_192f,
    slh_dsa_shake_192s, slh_dsa_shake_256f, slh_dsa_shake_256s, traits as slh_traits,
};

/// Supported ML-KEM parameter sets
pub const SUPPORTED_ML_KEM: &[&str] = &["ML-KEM-768"];

/// Supported ML-DSA parameter sets  
pub const SUPPORTED_ML_DSA: &[&str] = &["ML-DSA-65"];

/// Default security level provided by this library
pub const DEFAULT_SECURITY_LEVEL: &str = "NIST Level 3 (192-bit quantum security)";

/// Initialize the library with optimal settings
///
/// This function should be called once at application startup to configure
/// the library for optimal performance and security.
///
/// # Examples
///
/// ```no_run
/// // Initialize once at application startup
/// saorsa_pqc::init().expect("failed to initialize saorsa_pqc");
/// ```
/// Initialize the library with optimal settings
///
/// # Errors
/// Returns an error if initialization of internal components fails.
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging if available
    // Note: Logging setup is application-specific, not library-specific

    // Initialize memory pools (always enabled)
    pqc::memory_pool::initialize_global_pool()?;

    // Validate algorithm availability - always available now
    // Test that we can create algorithm instances
    let _ml_kem = pqc::MlKem768::new();
    let _ml_dsa = pqc::MlDsa65::new();

    Ok(())
}

/// Get library information and capabilities
///
/// Returns information about the library version, supported algorithms,
/// available features, and compatibility information.
#[must_use]
pub fn get_info() -> LibraryInfo {
    // Parse version string to extract major.minor.patch
    let version_parts: Vec<&str> = VERSION.split('.').collect();
    let (major, minor, patch) = if version_parts.len() >= 3 {
        (
            version_parts.first().unwrap_or(&"0").parse().unwrap_or(0),
            version_parts.get(1).unwrap_or(&"3").parse().unwrap_or(3),
            version_parts.get(2).unwrap_or(&"6").parse().unwrap_or(6),
        )
    } else {
        (0, 3, 6) // Default fallback
    };

    LibraryInfo {
        version: VERSION.to_string(),
        supported_ml_kem: SUPPORTED_ML_KEM.iter().map(|s| (*s).to_string()).collect(),
        supported_ml_dsa: SUPPORTED_ML_DSA.iter().map(|s| (*s).to_string()).collect(),
        features: get_enabled_features(),
        security_level: DEFAULT_SECURITY_LEVEL.to_string(),
        api_version: ApiCompatibilityInfo {
            major,
            minor,
            patch,
            min_supported_version: "0.3.0".to_string(), // Maintain compatibility back to 0.3.0
            stability: "stable".to_string(),
        },
        dependencies: DependencyVersionInfo {
            fips203_version: "0.4".to_string(), // Track major.minor for compatibility
            fips204_version: "0.4".to_string(), // Track major.minor for compatibility
            fips205_version: "0.4".to_string(), // Track major.minor for compatibility
            bincode_version: "2.0".to_string(), // Major version for compatibility tracking
            serde_version: "1.0".to_string(),   // Major version for compatibility tracking
        },
    }
}

/// Information about the library capabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryInfo {
    /// Library version
    pub version: String,
    /// Supported ML-KEM parameter sets
    pub supported_ml_kem: Vec<String>,
    /// Supported ML-DSA parameter sets
    pub supported_ml_dsa: Vec<String>,
    /// Enabled features
    pub features: Vec<String>,
    /// Default security level
    pub security_level: String,
    /// API compatibility information
    pub api_version: ApiCompatibilityInfo,
    /// Core dependency versions for compatibility tracking
    pub dependencies: DependencyVersionInfo,
}

/// API compatibility and version tracking information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCompatibilityInfo {
    /// Current API major version
    pub major: u32,
    /// Current API minor version  
    pub minor: u32,
    /// Current API patch version
    pub patch: u32,
    /// Minimum supported API version for backwards compatibility
    pub min_supported_version: String,
    /// API stability level
    pub stability: String,
}

/// Core dependency versions for backwards compatibility tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyVersionInfo {
    /// FIPS 203 (ML-KEM) crate version
    pub fips203_version: String,
    /// FIPS 204 (ML-DSA) crate version
    pub fips204_version: String,
    /// FIPS 205 (SLH-DSA) crate version
    pub fips205_version: String,
    /// Bincode version for serialization compatibility
    pub bincode_version: String,
    /// Serde version for serialization compatibility
    pub serde_version: String,
}

impl ApiCompatibilityInfo {
    /// Check if this API version is compatible with a minimum required version
    #[must_use]
    pub fn is_compatible_with(&self, min_version: &str) -> bool {
        use std::cmp::Ordering;
        // Parse the minimum version string
        let min_parts: Vec<&str> = min_version.split('.').collect();
        if min_parts.len() < 3 {
            return false;
        }

        let Ok(min_major) = min_parts.first().unwrap_or(&"0").parse::<u32>() else {
            return false;
        };
        let Ok(min_minor) = min_parts.get(1).unwrap_or(&"0").parse::<u32>() else {
            return false;
        };
        let Ok(min_patch) = min_parts.get(2).unwrap_or(&"0").parse::<u32>() else {
            return false;
        };

        // Check compatibility using semantic versioning rules
        match self.major.cmp(&min_major) {
            Ordering::Greater => true,
            Ordering::Equal => match self.minor.cmp(&min_minor) {
                Ordering::Greater => true,
                Ordering::Equal => self.patch >= min_patch,
                Ordering::Less => false,
            },
            Ordering::Less => false,
        }
    }

    /// Get the full version string
    #[must_use]
    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Check if the current library version supports backward compatibility with a specific version
#[must_use]
pub fn is_compatible_with_version(required_version: &str) -> bool {
    get_info().api_version.is_compatible_with(required_version)
}

/// Get the list of enabled features
fn get_enabled_features() -> Vec<String> {
    #[allow(unused_mut)]
    let mut features: Vec<String> = vec![
        // Core features always enabled
        "pqc".to_string(),
        "parallel".to_string(),
        "memory-pool".to_string(),
        "secure-memory".to_string(),
        "constant-time".to_string(),
        "hpke-support".to_string(),
        "extended-crypto".to_string(),
    ];

    #[cfg(feature = "simd")]
    {
        features.push("simd".to_string());
    }

    #[cfg(feature = "cert_compression")]
    {
        features.push("cert_compression".to_string());
    }

    #[cfg(feature = "dangerous_configuration")]
    {
        features.push("dangerous_configuration".to_string());
    }

    features
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_library_init() {
        let result = init();
        assert!(result.is_ok(), "Library initialization should succeed");
    }

    #[test]
    fn test_get_info() {
        let info = get_info();
        assert_eq!(info.version, VERSION);
        assert!(info.supported_ml_kem.contains(&"ML-KEM-768".to_string()));
        assert!(info.supported_ml_dsa.contains(&"ML-DSA-65".to_string()));
        assert!(!info.features.is_empty());

        // Test new version tracking fields
        assert_eq!(info.api_version.stability, "stable");
        assert_eq!(info.api_version.min_supported_version, "0.3.0");
        assert!(!info.dependencies.fips203_version.is_empty());
        assert!(!info.dependencies.fips204_version.is_empty());
        assert!(!info.dependencies.fips205_version.is_empty());
    }

    #[test]
    fn test_version_compatibility() {
        let info = get_info();

        // Test compatibility with older versions
        assert!(info.api_version.is_compatible_with("0.3.0"));
        assert!(info.api_version.is_compatible_with("0.3.1"));

        // Test compatibility with current version
        assert!(info
            .api_version
            .is_compatible_with(&info.api_version.version_string()));

        // Test public API function
        assert!(is_compatible_with_version("0.3.0"));

        // Test invalid version string handling
        assert!(!info.api_version.is_compatible_with("invalid"));
        assert!(!info.api_version.is_compatible_with("1.0"));
    }

    #[test]
    fn test_enabled_features() {
        let features = get_enabled_features();
        assert!(
            !features.is_empty(),
            "Should have at least one feature enabled"
        );
    }

    #[test]
    #[allow(clippy::const_is_empty)]
    fn test_constants() {
        assert!(!SUPPORTED_ML_KEM.is_empty());
        assert!(!SUPPORTED_ML_DSA.is_empty());
        assert!(!DEFAULT_SECURITY_LEVEL.is_empty());
        assert!(!VERSION.is_empty());
    }
}
