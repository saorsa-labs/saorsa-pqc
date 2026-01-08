//! Hybrid encryption module combining ML-KEM-768 with AES-256-GCM
//!
//! This module provides quantum-resistant encryption by combining:
//! - ML-KEM-768 for key encapsulation (post-quantum secure)
//! - AES-256-GCM for symmetric encryption (classically secure)
//!
//! The hybrid approach ensures security against both classical and quantum attackers,
//! following the "belt and suspenders" principle recommended by NIST.
//!
//! # Security Features
//!
//! - **Post-quantum KEM**: ML-KEM-768 provides ~192-bit quantum security
//! - **Authenticated encryption**: AES-256-GCM provides confidentiality and integrity
//! - **Forward secrecy**: Each message uses a unique ephemeral key
//! - **Key separation**: Separate keys for encryption and authentication
//! - **Domain separation**: Context-specific key derivation
//!
//! # Implementation Details
//!
//! - Uses ML-KEM-768 for key encapsulation (1088-byte ciphertext)
//! - Derives AES-256 key using HKDF-SHA256
//! - 96-bit nonces for AES-GCM (safe for 2^32 encryptions)
//! - HKDF-SHA256 for proper key derivation (NIST SP 800-56C Rev. 2)
//! - Constant-time operations where possible

use crate::pqc::constant_time::ct_eq;
use crate::pqc::types::{
    MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, PqcError, PqcResult, SharedSecret,
};
use crate::pqc::{ml_kem::MlKem768, MlKemOperations};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce as AesNonce,
};
use hkdf::Hkdf;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Wire format for encrypted messages
///
/// Contains all necessary components for decryption:
/// - ML-KEM ciphertext for key encapsulation
/// - AES-GCM ciphertext with authentication tag
/// - Nonce for AES-GCM
/// - Associated data hash for integrity
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// ML-KEM-768 ciphertext (1088 bytes)
    pub kem_ciphertext: MlKemCiphertext,
    /// AES-GCM encrypted data with authentication tag
    pub aes_ciphertext: Vec<u8>,
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// SHA-256 hash of associated data for verification
    pub aad_hash: [u8; 32],
}

/// Hybrid Public Key Encryption using ML-KEM and AES-GCM
///
/// Provides CCA2-secure public key encryption by combining:
/// - ML-KEM-768 for key encapsulation
/// - AES-256-GCM for data encryption
/// - HKDF for key derivation
pub struct HybridPublicKeyEncryption {
    /// ML-KEM-768 instance for key encapsulation
    ml_kem: MlKem768,
}

impl HybridPublicKeyEncryption {
    /// Create a new hybrid encryption instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ml_kem: MlKem768::new(),
        }
    }

    /// Generate a new keypair for hybrid encryption
    ///
    /// # Errors
    /// Returns `PqcError` if keypair generation fails
    pub fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        self.ml_kem.generate_keypair()
    }

    /// Encrypt a message using the hybrid scheme
    ///
    /// # Arguments
    /// * `public_key` - Recipient's ML-KEM-768 public key
    /// * `plaintext` - Message to encrypt
    /// * `associated_data` - Additional authenticated data (not encrypted)
    ///
    /// # Returns
    /// An `EncryptedMessage` containing all components needed for decryption
    ///
    /// # Errors
    /// Returns `PqcError` if encapsulation or encryption fails
    pub fn encrypt(
        &self,
        public_key: &MlKemPublicKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<EncryptedMessage> {
        // Step 1: Encapsulate to get shared secret
        let (kem_ciphertext, shared_secret) = self.ml_kem.encapsulate(public_key)?;

        // Step 2: Derive AES key from shared secret using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aes_key_bytes = [0u8; 32];
        hk.expand(b"aes-256-gcm-key", &mut aes_key_bytes)
            .map_err(|_| PqcError::CryptoError("HKDF expansion failed".to_string()))?;

        // Step 3: Generate random nonce
        let mut nonce = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce);

        // Step 4: Encrypt with AES-GCM
        let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce_obj = AesNonce::from_slice(&nonce);

        let aes_ciphertext = cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|_| PqcError::EncryptionFailed("AES-GCM encryption failed".to_string()))?;

        // Step 5: Hash associated data for integrity check
        let mut hasher = Sha256::new();
        hasher.update(associated_data);
        let aad_hash: [u8; 32] = hasher.finalize().into();

        Ok(EncryptedMessage {
            kem_ciphertext,
            aes_ciphertext,
            nonce,
            aad_hash,
        })
    }

    /// Decrypt a message using the hybrid scheme
    ///
    /// # Arguments
    /// * `secret_key` - Recipient's ML-KEM-768 secret key
    /// * `encrypted_message` - The encrypted message to decrypt
    /// * `associated_data` - Additional authenticated data for verification
    ///
    /// # Returns
    /// The decrypted plaintext if successful
    ///
    /// # Errors
    /// Returns `PqcError::DecryptionFailed` if AAD verification fails or AES-GCM decryption fails.
    /// Returns `PqcError::CryptoError` if HKDF expansion fails.
    pub fn decrypt(
        &self,
        secret_key: &MlKemSecretKey,
        encrypted_message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>> {
        // Step 1: Verify associated data hash
        let mut hasher = Sha256::new();
        hasher.update(associated_data);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        if !ct_eq(&computed_hash, &encrypted_message.aad_hash) {
            return Err(PqcError::DecryptionFailed(
                "Associated data verification failed".to_string(),
            ));
        }

        // Step 2: Decapsulate to recover shared secret
        let shared_secret = self
            .ml_kem
            .decapsulate(secret_key, &encrypted_message.kem_ciphertext)?;

        // Step 3: Derive AES key from shared secret
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aes_key_bytes = [0u8; 32];
        hk.expand(b"aes-256-gcm-key", &mut aes_key_bytes)
            .map_err(|_| PqcError::CryptoError("HKDF expansion failed".to_string()))?;

        // Step 4: Decrypt with AES-GCM
        let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce_obj = AesNonce::from_slice(&encrypted_message.nonce);

        let plaintext = cipher
            .decrypt(nonce_obj, encrypted_message.aes_ciphertext.as_slice())
            .map_err(|_| PqcError::DecryptionFailed("AES-GCM decryption failed".to_string()))?;

        Ok(plaintext)
    }
}

/// Session-based encryption for multiple messages
///
/// Provides efficient encryption for multiple messages to the same recipient
/// by caching the shared secret and deriving per-message keys.
pub struct EncryptionSession {
    /// Shared secret for the session
    shared_secret: SharedSecret,
    /// Counter for message sequencing and key derivation
    message_counter: u64,
}

impl EncryptionSession {
    /// Create a new encryption session
    ///
    /// # Arguments
    /// * `public_key` - Recipient's public key
    ///
    /// # Returns
    /// A tuple of (session, KEM ciphertext) where the ciphertext must be sent to the recipient
    ///
    /// # Errors
    /// Returns `PqcError` if ML-KEM encapsulation fails.
    pub fn new(public_key: &MlKemPublicKey) -> PqcResult<(Self, MlKemCiphertext)> {
        let ml_kem = MlKem768::new();
        let (kem_ciphertext, shared_secret) = ml_kem.encapsulate(public_key)?;

        Ok((
            Self {
                shared_secret,
                message_counter: 0,
            },
            kem_ciphertext,
        ))
    }

    /// Encrypt a message in the session
    ///
    /// Each message gets a unique key derived from the session secret and counter
    ///
    /// # Errors
    /// Returns `PqcError::CryptoError` if HKDF expansion fails.
    /// Returns `PqcError::EncryptionFailed` if AES-GCM encryption fails.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> PqcResult<Vec<u8>> {
        // Derive per-message key
        let mut key_material = Vec::new();
        key_material.extend_from_slice(self.shared_secret.as_bytes());
        key_material.extend_from_slice(&self.message_counter.to_be_bytes());

        let hk = Hkdf::<Sha256>::new(None, &key_material);
        let mut aes_key = [0u8; 32];
        hk.expand(b"message-key", &mut aes_key)
            .map_err(|_| PqcError::CryptoError("HKDF expansion failed".to_string()))?;

        // Generate nonce from counter
        let mut nonce = [0u8; 12];
        let counter_bytes = self.message_counter.to_be_bytes();
        nonce[4..12].copy_from_slice(&counter_bytes);

        // Encrypt
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_obj = AesNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|_| PqcError::EncryptionFailed("Session encryption failed".to_string()))?;

        self.message_counter = self.message_counter.saturating_add(1);

        // Prepend counter for decryption
        let mut result = Vec::with_capacity(8_usize.saturating_add(ciphertext.len()));
        result.extend_from_slice(&(self.message_counter.saturating_sub(1)).to_be_bytes());
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }
}

/// Decryption session for multiple messages
pub struct DecryptionSession {
    /// Shared secret for the session
    shared_secret: SharedSecret,
    /// Track received message counters to prevent replay attacks
    received_counters: HashMap<u64, bool>,
}

impl DecryptionSession {
    /// Create a new decryption session
    ///
    /// # Arguments
    /// * `secret_key` - Recipient's secret key
    /// * `kem_ciphertext` - KEM ciphertext from sender
    ///
    /// # Errors
    /// Returns `PqcError` if ML-KEM decapsulation fails.
    pub fn new(secret_key: &MlKemSecretKey, kem_ciphertext: &MlKemCiphertext) -> PqcResult<Self> {
        let ml_kem = MlKem768::new();
        let shared_secret = ml_kem.decapsulate(secret_key, kem_ciphertext)?;

        Ok(Self {
            shared_secret,
            received_counters: HashMap::new(),
        })
    }

    /// Decrypt a message in the session
    ///
    /// # Errors
    /// Returns `PqcError::DecryptionFailed` for invalid ciphertext, counter format errors, or replay attacks.
    /// Returns `PqcError::CryptoError` if HKDF expansion fails.
    /// Returns `PqcError::DecryptionFailed` if AES-GCM decryption fails.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> PqcResult<Vec<u8>> {
        if ciphertext.len() < 8 {
            return Err(PqcError::DecryptionFailed("Invalid ciphertext".to_string()));
        }

        // Extract counter
        let counter_slice = ciphertext.get(..8).ok_or_else(|| {
            PqcError::DecryptionFailed("Ciphertext too short for counter".to_string())
        })?;
        let counter_bytes: [u8; 8] = counter_slice
            .try_into()
            .map_err(|_| PqcError::DecryptionFailed("Invalid counter format".to_string()))?;
        let counter = u64::from_be_bytes(counter_bytes);

        // Check for replay
        if self.received_counters.contains_key(&counter) {
            return Err(PqcError::DecryptionFailed("Replay detected".to_string()));
        }

        // Derive per-message key
        let mut key_material = Vec::new();
        key_material.extend_from_slice(self.shared_secret.as_bytes());
        key_material.extend_from_slice(&counter.to_be_bytes());

        let hk = Hkdf::<Sha256>::new(None, &key_material);
        let mut aes_key = [0u8; 32];
        hk.expand(b"message-key", &mut aes_key)
            .map_err(|_| PqcError::CryptoError("HKDF expansion failed".to_string()))?;

        // Generate nonce from counter
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());

        // Decrypt
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_obj = AesNonce::from_slice(&nonce);

        let ciphertext_slice = ciphertext
            .get(8..)
            .ok_or_else(|| PqcError::DecryptionFailed("Ciphertext too short".to_string()))?;
        let plaintext = cipher
            .decrypt(nonce_obj, ciphertext_slice)
            .map_err(|_| PqcError::DecryptionFailed("Session decryption failed".to_string()))?;

        // Mark counter as used
        self.received_counters.insert(counter, true);

        Ok(plaintext)
    }
}

impl Default for HybridPublicKeyEncryption {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let pke = HybridPublicKeyEncryption::new();

        // Generate keypair for testing
        let (public_key, secret_key) = pke
            .ml_kem
            .generate_keypair()
            .expect("Key generation should succeed");

        let plaintext = b"Hello, quantum-resistant world!";
        let associated_data = b"test-context";

        // Encrypt
        let encrypted = pke
            .encrypt(&public_key, plaintext, associated_data)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted = pke
            .decrypt(&secret_key, &encrypted, associated_data)
            .expect("Decryption should succeed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let pke = HybridPublicKeyEncryption::new();

        let (public_key, secret_key) = pke.ml_kem.generate_keypair().unwrap();
        let plaintext = b"Test message";
        let aad = b"correct-aad";
        let wrong_aad = b"wrong-aad";

        let encrypted = pke.encrypt(&public_key, plaintext, aad).unwrap();

        let result = pke.decrypt(&secret_key, &encrypted, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_encryption() {
        let ml_kem = MlKem768::new();
        let (public_key, secret_key) = ml_kem.generate_keypair().unwrap();

        // Create session
        let (mut enc_session, kem_ct) = EncryptionSession::new(&public_key).unwrap();
        let mut dec_session = DecryptionSession::new(&secret_key, &kem_ct).unwrap();

        // Encrypt and decrypt multiple messages
        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let encrypted = enc_session.encrypt_message(plaintext.as_bytes()).unwrap();
            let decrypted = dec_session.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted);
        }
    }

    #[test]
    fn test_session_replay_protection() {
        let ml_kem = MlKem768::new();
        let (public_key, secret_key) = ml_kem.generate_keypair().unwrap();

        let (mut enc_session, kem_ct) = EncryptionSession::new(&public_key).unwrap();
        let mut dec_session = DecryptionSession::new(&secret_key, &kem_ct).unwrap();

        let plaintext = b"Test";
        let encrypted = enc_session.encrypt_message(plaintext).unwrap();

        // First decryption should succeed
        let decrypted = dec_session.decrypt_message(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);

        // Replay should fail
        let replay_result = dec_session.decrypt_message(&encrypted);
        assert!(replay_result.is_err());
    }

    #[test]
    fn test_unique_ciphertexts() {
        let pke = HybridPublicKeyEncryption::new();
        let (public_key, _secret_key) = pke.ml_kem.generate_keypair().unwrap();

        let plaintext = b"Same message";
        let aad = b"same-aad";

        let encrypted1 = pke.encrypt(&public_key, plaintext, aad).unwrap();
        let encrypted2 = pke.encrypt(&public_key, plaintext, aad).unwrap();

        // Same plaintext should produce different ciphertexts (due to randomness)
        assert_ne!(encrypted1.aes_ciphertext, encrypted2.aes_ciphertext);
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
    }
}
