//! Example demonstrating HKDF (HMAC-based Key Derivation Function) usage
//!
//! This example shows how to use HKDF with SHA3 for quantum-resistant key derivation
//! in various cryptographic scenarios, including key exchange, session keys, and
//! password-based key derivation.

use saorsa_pqc::api::traits::Kdf;
use saorsa_pqc::{kdf_helpers, HkdfSha3_256, HkdfSha3_512, KdfAlgorithm};
use saorsa_pqc::{MlKem768, MlKemOperations};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HKDF Key Derivation Examples ===\n");

    // Example 1: Basic HKDF usage with SHA3-256
    basic_hkdf_example()?;

    // Example 2: Deriving encryption and authentication keys
    derive_enc_auth_keys_example()?;

    // Example 3: Key stretching for session keys
    key_stretching_example()?;

    // Example 4: Hierarchical key derivation
    key_hierarchy_example()?;

    // Example 5: HKDF with ML-KEM shared secret
    ml_kem_with_hkdf_example()?;

    // Example 6: Password-based key derivation
    password_derivation_example()?;

    // Example 7: Extract and expand separately
    extract_expand_example()?;

    Ok(())
}

fn basic_hkdf_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Basic HKDF Usage");
    println!("-------------------");

    let initial_key_material = b"shared secret from key exchange";
    let salt = b"application-specific salt";
    let info = b"session key v1";

    // Derive a 32-byte key using HKDF-SHA3-256
    let mut session_key = [0u8; 32];
    HkdfSha3_256::derive(initial_key_material, Some(salt), info, &mut session_key)?;

    println!("Input Key Material: {} bytes", initial_key_material.len());
    println!("Salt: {:?}", std::str::from_utf8(salt)?);
    println!("Info: {:?}", std::str::from_utf8(info)?);
    println!("Derived Session Key: {} bytes", session_key.len());
    println!("First 8 bytes: {:02x?}", &session_key[..8]);

    // Using the enum interface for algorithm selection
    let key_via_enum =
        KdfAlgorithm::HkdfSha3_256.derive(initial_key_material, Some(salt), info, 32)?;
    assert_eq!(&session_key[..], &key_via_enum[..]);
    println!("✓ Enum interface produces identical output\n");

    Ok(())
}

fn derive_enc_auth_keys_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("2. Deriving Encryption and Authentication Keys");
    println!("-----------------------------------------------");

    let shared_secret = b"negotiated shared secret from ECDHE or ML-KEM";
    let context = b"TLS 1.3 derived keys";

    let (enc_key, auth_key) = kdf_helpers::derive_enc_auth_keys(shared_secret, context)?;

    println!("Shared Secret: {} bytes", shared_secret.len());
    println!("Context: {:?}", std::str::from_utf8(context)?);
    println!("Encryption Key: {} bytes", enc_key.len());
    println!("Auth Key: {} bytes", auth_key.len());
    println!("Enc Key (first 8): {:02x?}", &enc_key[..8]);
    println!("Auth Key (first 8): {:02x?}", &auth_key[..8]);
    println!("✓ Keys are different: {}\n", enc_key != auth_key);

    Ok(())
}

fn key_stretching_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("3. Key Stretching");
    println!("-----------------");

    let short_key = b"short_key";
    let label = b"stretched for AES-256";

    // Stretch a short key to 64 bytes
    let stretched = kdf_helpers::stretch_key(short_key, label, 64)?;

    println!("Original Key: {} bytes", short_key.len());
    println!("Label: {:?}", std::str::from_utf8(label)?);
    println!("Stretched Key: {} bytes", stretched.len());
    println!("First 16 bytes: {:02x?}", &stretched[..16]);

    // Different labels produce different outputs
    let stretched2 = kdf_helpers::stretch_key(short_key, b"different purpose", 64)?;
    println!(
        "✓ Different labels give different keys: {}\n",
        stretched != stretched2
    );

    Ok(())
}

fn key_hierarchy_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("4. Hierarchical Key Derivation");
    println!("-------------------------------");

    let master_key = b"application master key";
    let labels = vec![
        b"encryption".as_slice(),
        b"authentication".as_slice(),
        b"integrity".as_slice(),
        b"key_exchange".as_slice(),
    ];

    let derived_keys = kdf_helpers::derive_key_hierarchy(master_key, &labels)?;

    println!("Master Key: {} bytes", master_key.len());
    println!("Deriving {} keys:", labels.len());

    for (i, (label, key)) in labels.iter().zip(derived_keys.iter()).enumerate() {
        println!(
            "  {}. {:20} -> {} bytes, first 4: {:02x?}",
            i + 1,
            std::str::from_utf8(label)?,
            key.len(),
            &key[..4]
        );
    }

    // Verify all keys are unique
    let mut all_unique = true;
    for i in 0..derived_keys.len() {
        for j in (i + 1)..derived_keys.len() {
            if derived_keys[i] == derived_keys[j] {
                all_unique = false;
                break;
            }
        }
    }
    println!("✓ All derived keys are unique: {}\n", all_unique);

    Ok(())
}

fn ml_kem_with_hkdf_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("5. ML-KEM with HKDF");
    println!("-------------------");

    // Generate ML-KEM keypair
    let ml_kem = MlKem768::new();
    let (pub_key, sec_key) = ml_kem.generate_keypair()?;

    // Encapsulate to get shared secret
    let (ciphertext, shared_secret) = ml_kem.encapsulate(&pub_key)?;

    // Use HKDF to derive multiple keys from the ML-KEM shared secret
    let context = b"ML-KEM-768 key derivation v1";
    let (enc_key, mac_key) = kdf_helpers::derive_enc_auth_keys(shared_secret.as_bytes(), context)?;

    println!(
        "ML-KEM-768 Shared Secret: {} bytes",
        shared_secret.as_bytes().len()
    );
    println!("Derived Encryption Key: {} bytes", enc_key.len());
    println!("Derived MAC Key: {} bytes", mac_key.len());

    // Derive additional keys for different purposes
    let labels = vec![
        b"client_write_key".as_slice(),
        b"server_write_key".as_slice(),
        b"client_write_iv".as_slice(),
        b"server_write_iv".as_slice(),
    ];

    let traffic_keys = kdf_helpers::derive_key_hierarchy(shared_secret.as_bytes(), &labels)?;
    println!("\nDerived Traffic Keys:");
    for (label, key) in labels.iter().zip(traffic_keys.iter()) {
        println!(
            "  {:20} -> {} bytes",
            std::str::from_utf8(label)?,
            key.len()
        );
    }

    // Verify decapsulation produces same shared secret
    let recovered = ml_kem.decapsulate(&sec_key, &ciphertext)?;
    println!(
        "✓ Decapsulation verified: {}\n",
        shared_secret.as_bytes() == recovered.as_bytes()
    );

    Ok(())
}

fn password_derivation_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("6. Password-Based Key Derivation");
    println!("---------------------------------");

    let password = b"user_passphrase_2024";
    let salt = b"random_salt_value_minimum_16_bytes";
    let iterations = 10_000; // Use 100,000+ in production

    let derived_key = kdf_helpers::derive_key_from_password(password, salt, iterations)?;

    println!("Password: {} characters", password.len());
    println!("Salt: {} bytes", salt.len());
    println!("Iterations: {}", iterations);
    println!("Derived Key: {} bytes", derived_key.len());
    println!("First 8 bytes: {:02x?}", &derived_key[..8]);

    // Different salt produces different key
    let different_salt = b"another_random_salt_value_16_bytes+";
    let derived_key2 = kdf_helpers::derive_key_from_password(password, different_salt, iterations)?;
    println!(
        "✓ Different salt gives different key: {}",
        derived_key != derived_key2
    );

    // More iterations increases security but takes more time
    let start = std::time::Instant::now();
    let _ = kdf_helpers::derive_key_from_password(password, salt, iterations * 10)?;
    let duration = start.elapsed();
    println!("Time for {}x iterations: {:?}\n", 10, duration);

    Ok(())
}

fn extract_expand_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("7. Extract and Expand Separately");
    println!("---------------------------------");

    let ikm = b"input key material from ECDHE";
    let salt = b"protocol-specific salt";

    // Extract phase: create a pseudo-random key (PRK)
    let prk = HkdfSha3_512::extract(Some(salt), ikm);
    println!("Input Key Material: {} bytes", ikm.len());
    println!("Salt: {} bytes", salt.len());
    println!("Extracted PRK: {} bytes", prk.len());

    // Expand phase: derive multiple keys from the same PRK
    let contexts = vec![
        b"handshake traffic secret".as_slice(),
        b"application traffic secret".as_slice(),
        b"exporter master secret".as_slice(),
    ];

    println!("\nExpanding PRK to multiple keys:");
    for context in &contexts {
        let mut key = [0u8; 32];
        HkdfSha3_512::expand(&prk, context, &mut key)?;
        println!(
            "  {:30} -> first 8 bytes: {:02x?}",
            std::str::from_utf8(context)?,
            &key[..8]
        );
    }

    // Verify extract+expand equals direct derive
    let mut okm_direct = [0u8; 32];
    HkdfSha3_512::derive(ikm, Some(salt), contexts[0], &mut okm_direct)?;

    let mut okm_two_phase = [0u8; 32];
    HkdfSha3_512::expand(&prk, contexts[0], &mut okm_two_phase)?;

    println!(
        "\n✓ Extract+Expand equals Derive: {}",
        okm_direct == okm_two_phase
    );

    Ok(())
}
