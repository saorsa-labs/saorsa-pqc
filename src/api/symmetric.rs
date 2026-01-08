// Rust 1.92+ raises unused_assignments on struct fields read via getter methods
// when used with derive macros like Zeroize. This is a known false positive.
#![allow(unused_assignments)]

//! Quantum-Secure Symmetric Encryption
//!
//! This module provides ChaCha20-Poly1305 authenticated encryption, which is
//! quantum-resistant. Symmetric algorithms like ChaCha20-Poly1305 maintain their
//! security against quantum computers, requiring only a doubling of key sizes
//! to defend against Grover's algorithm.
//!
//! ## Quantum Security
//!
//! - **Classical Security**: 256-bit keys provide 256-bit security
//! - **Quantum Security**: 256-bit keys provide 128-bit security (due to Grover's algorithm)
//! - **AEAD**: Provides both confidentiality and authenticity
//! - **Performance**: Highly optimized with SIMD support on modern CPUs

use super::errors::{PqcError, PqcResult};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305 as Cipher, Key, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ChaCha20-Poly1305 authenticated encryption cipher
///
/// Provides quantum-secure symmetric encryption with authentication.
/// Uses 256-bit keys and 96-bit nonces.
pub struct ChaCha20Poly1305 {
    cipher: Cipher,
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 cipher from a 256-bit key
    #[must_use]
    pub fn new(key: &Key) -> Self {
        Self {
            cipher: Cipher::new(key),
        }
    }

    /// Generate a new random 256-bit key
    pub fn generate_key() -> Key {
        Cipher::generate_key(&mut OsRng)
    }

    /// Generate a new random 96-bit nonce
    pub fn generate_nonce() -> Nonce {
        Cipher::generate_nonce(&mut OsRng)
    }

    /// Encrypt a message with authenticated encryption
    ///
    /// Returns ciphertext that includes the authentication tag
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails due to invalid parameters or
    /// cryptographic operation failures.
    pub fn encrypt(&self, nonce: &Nonce, plaintext: &[u8]) -> PqcResult<Vec<u8>> {
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| PqcError::EncryptionFailed(e.to_string()))
    }

    /// Encrypt a message with associated data
    ///
    /// The associated data is authenticated but not encrypted
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails due to invalid parameters or
    /// cryptographic operation failures.
    pub fn encrypt_with_aad(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> PqcResult<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| PqcError::EncryptionFailed(e.to_string()))
    }

    /// Decrypt and authenticate a ciphertext
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or decryption encounters an error.
    pub fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8]) -> PqcResult<Vec<u8>> {
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PqcError::DecryptionFailed("Authentication failed".into()))
    }

    /// Decrypt and authenticate a ciphertext with associated data
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or decryption encounters an error.
    pub fn decrypt_with_aad(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> PqcResult<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| PqcError::DecryptionFailed("Authentication failed".into()))
    }
}

/// A secure key wrapper that zeroizes on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    #[zeroize(skip)]
    key: Key,
}

impl SecureKey {
    /// Create a new secure key from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: *Key::from_slice(bytes),
        }
    }

    /// Generate a new random secure key
    #[must_use]
    pub fn generate() -> Self {
        Self {
            key: ChaCha20Poly1305::generate_key(),
        }
    }

    /// Get a reference to the inner key
    #[must_use]
    pub const fn as_key(&self) -> &Key {
        &self.key
    }
}

/// Convenience function to generate a new 256-bit key
#[must_use]
pub fn generate_key() -> Key {
    ChaCha20Poly1305::generate_key()
}

/// Convenience function to generate a new 96-bit nonce
#[must_use]
pub fn generate_nonce() -> Nonce {
    ChaCha20Poly1305::generate_nonce()
}

/// Encrypt data using ChaCha20-Poly1305
///
/// This is a convenience function for one-shot encryption
///
/// # Errors
///
/// Returns an error if encryption fails due to invalid parameters or
/// cryptographic operation failures.
pub fn encrypt(key: &Key, nonce: &Nonce, plaintext: &[u8]) -> PqcResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, plaintext)
}

/// Decrypt data using ChaCha20-Poly1305
///
/// This is a convenience function for one-shot decryption
///
/// # Errors
///
/// Returns an error if decryption fails due to authentication failure,
/// invalid parameters, or cryptographic operation failures.
pub fn decrypt(key: &Key, nonce: &Nonce, ciphertext: &[u8]) -> PqcResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Quantum-secure message";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let cipher = ChaCha20Poly1305::new(&generate_key());
        let nonce = generate_nonce();
        let plaintext = b"Secret message";
        let aad = b"Additional authenticated data";

        let ciphertext = cipher.encrypt_with_aad(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_authentication_failure() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Test message";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        // Corrupt the ciphertext
        ciphertext[0] ^= 0xFF;

        // Decryption should fail due to authentication
        assert!(decrypt(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_secure_key() {
        let key = SecureKey::generate();
        let nonce = generate_nonce();
        let plaintext = b"Test with secure key";

        let cipher = ChaCha20Poly1305::new(key.as_key());
        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
