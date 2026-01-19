use anyhow::{Result, anyhow};
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use hkdf::Hkdf;
use p384::{PublicKey, SecretKey, ecdh::diffie_hellman};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use sha2::Sha256;

/// P-384 encryption key pair for attestation and ECDH-based encryption
/// Used for ECDH key exchange to encrypt data to/from the enclave
pub struct EncryptionKey {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl EncryptionKey {
    /// Generate new P-384 key pair
    pub fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        Self { secret_key, public_key }
    }

    /// Generate P-384 key pair from entropy (for NSM RNG)
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        // Use entropy to seed the RNG for key generation
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        
        // Take first 32 bytes as seed
        let mut seed = [0u8; 32];
        let len = entropy.len().min(32);
        seed[..len].copy_from_slice(&entropy[..len]);
        
        let mut rng = ChaCha20Rng::from_seed(seed);
        let secret_key = SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        Ok(Self { secret_key, public_key })
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Raw SEC1-encoded uncompressed public key (97 bytes: 0x04 + 96 bytes)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// DER-encoded SubjectPublicKeyInfo for NSM attestation
    /// Constructs a DER-encoded SPKI with P-384 (secp384r1) OID
    /// 
    /// Structure:
    /// SubjectPublicKeyInfo ::= SEQUENCE {
    ///   algorithm AlgorithmIdentifier,
    ///   subjectPublicKey BIT STRING
    /// }
    /// AlgorithmIdentifier ::= SEQUENCE {
    ///   algorithm OBJECT IDENTIFIER,  -- 1.2.840.10045.2.1 (EC public key)
    ///   parameters OBJECT IDENTIFIER   -- 1.3.132.0.34 (secp384r1/P-384)
    /// }
    pub fn public_key_as_der(&self) -> Result<Vec<u8>> {
        // OID encodings:
        // 1.2.840.10045.2.1 (EC public key) = 06 07 2a 86 48 ce 3d 02 01
        // 1.3.132.0.34 (secp384r1/P-384) = 06 05 2b 81 04 00 22
        let oid_ec_pubkey: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let oid_secp384r1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        
        // Get SEC1-encoded uncompressed public key (97 bytes: 0x04 + 96 bytes)
        let encoded_point = self.public_key.to_encoded_point(false);
        let pub_key_bytes = encoded_point.as_bytes();
        
        // AlgorithmIdentifier SEQUENCE: algorithm OID + parameters OID
        let alg_seq_len = oid_ec_pubkey.len() + oid_secp384r1.len();
        let alg_seq = {
            let mut seq = Vec::with_capacity(2 + alg_seq_len);
            seq.push(0x30); // SEQUENCE tag
            seq.push(alg_seq_len as u8);
            seq.extend_from_slice(oid_ec_pubkey);
            seq.extend_from_slice(oid_secp384r1);
            seq
        };
        
        // BitString: unused_bits (1 byte) + public key bytes
        let bit_string_len = 1 + pub_key_bytes.len();
        let bit_string = {
            let mut bs = Vec::with_capacity(2 + bit_string_len);
            bs.push(0x03); // BIT STRING tag
            // Length encoding for values > 127
            if bit_string_len > 127 {
                bs.push(0x81); // Long form, 1 byte length
                bs.push(bit_string_len as u8);
            } else {
                bs.push(bit_string_len as u8);
            }
            bs.push(0x00); // unused_bits = 0
            bs.extend_from_slice(pub_key_bytes);
            bs
        };
        
        // SubjectPublicKeyInfo SEQUENCE: AlgorithmIdentifier + BitString
        let spki_len = alg_seq.len() + bit_string.len();
        let mut spki = Vec::with_capacity(4 + spki_len);
        spki.push(0x30); // SEQUENCE tag
        if spki_len > 127 {
            // Long form length encoding
            let len_bytes = (spki_len as u32).to_be_bytes();
            let len_bytes_needed = len_bytes.iter().skip_while(|&&b| b == 0).count();
            spki.push(0x80 | len_bytes_needed as u8);
            spki.extend_from_slice(&len_bytes[4 - len_bytes_needed..]);
        } else {
            spki.push(spki_len as u8);
        }
        spki.extend_from_slice(&alg_seq);
        spki.extend_from_slice(&bit_string);
        
        Ok(spki)
    }

    /// PEM-encoded public key for human-readable format
    pub fn public_key_as_pem(&self) -> Result<String> {
        let der = self.public_key_as_der()?;
        let b64 = general_purpose::STANDARD.encode(&der);
        
        // Split into 64-character lines
        let lines: Vec<&str> = b64.as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();
        
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            lines.join("\n")
        ))
    }

    /// Public key as hex string (for debugging/logging)
    pub fn public_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.public_key_bytes()))
    }

    /// Derive shared AES-256 key using ECDH + HKDF
    /// 
    /// Args:
    ///   peer_public_key_der: Peer's public key in DER (SPKI) format
    /// 
    /// Returns:
    ///   32-byte AES key
    fn derive_shared_key(&self, peer_public_key_der: &[u8]) -> Result<[u8; 32]> {
        // Parse DER-encoded SPKI to get the public key
        let peer_public_key = parse_der_public_key(peer_public_key_der)?;
        
        // Perform ECDH
        let shared_secret = diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            peer_public_key.as_affine()
        );
        
        // Derive AES key using HKDF-SHA256
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"encryption data", &mut aes_key)
            .map_err(|_| anyhow!("HKDF expand failed"))?;
        
        Ok(aes_key)
    }

    /// Decrypt data encrypted by a client using ECDH + AES-GCM
    /// 
    /// Args:
    ///   nonce: 12-byte nonce (or 32-byte, first 12 used)
    ///   client_public_key_der: Client's ephemeral public key (DER/SPKI format)
    ///   encrypted_data: AES-GCM encrypted ciphertext with tag
    /// 
    /// Returns:
    ///   Decrypted plaintext bytes
    pub fn decrypt(&self, nonce: &[u8], client_public_key_der: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // Derive shared key
        let aes_key = self.derive_shared_key(client_public_key_der)?;
        
        // Use first 12 bytes of nonce for AES-GCM (standard nonce size)
        let nonce_bytes = if nonce.len() >= 12 {
            &nonce[..12]
        } else {
            return Err(anyhow!("Nonce must be at least 12 bytes"));
        };
        
        // Decrypt using AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }

    /// Encrypt data to send to a client using ECDH + AES-GCM
    /// 
    /// Args:
    ///   plaintext: Data to encrypt
    ///   client_public_key_der: Client's public key (DER/SPKI format)
    ///   nonce: 12-byte nonce (or 32-byte, first 12 used)
    /// 
    /// Returns:
    ///   Encrypted ciphertext with authentication tag
    pub fn encrypt(&self, plaintext: &[u8], client_public_key_der: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        // Derive shared key
        let aes_key = self.derive_shared_key(client_public_key_der)?;
        
        // Use first 12 bytes of nonce for AES-GCM (standard nonce size)
        let nonce_bytes = if nonce.len() >= 12 {
            &nonce[..12]
        } else {
            return Err(anyhow!("Nonce must be at least 12 bytes"));
        };
        
        // Encrypt using AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        
        Ok(ciphertext)
    }
}

/// Parse a DER-encoded SubjectPublicKeyInfo to extract the P-384 public key
fn parse_der_public_key(der: &[u8]) -> Result<PublicKey> {
    // Simple DER parser for SPKI structure
    // SEQUENCE { AlgorithmIdentifier, BIT STRING }
    
    if der.len() < 4 || der[0] != 0x30 {
        return Err(anyhow!("Invalid DER: expected SEQUENCE"));
    }
    
    // Parse outer SEQUENCE length
    let (content_start, _content_len) = parse_der_length(&der[1..])?;
    let content = &der[1 + content_start..];
    
    // Skip AlgorithmIdentifier SEQUENCE
    if content.is_empty() || content[0] != 0x30 {
        return Err(anyhow!("Invalid DER: expected AlgorithmIdentifier SEQUENCE"));
    }
    let (alg_len_size, alg_len) = parse_der_length(&content[1..])?;
    let bit_string_start = 1 + alg_len_size + alg_len;
    
    if bit_string_start >= content.len() || content[bit_string_start] != 0x03 {
        return Err(anyhow!("Invalid DER: expected BIT STRING"));
    }
    
    // Parse BIT STRING
    let bit_string = &content[bit_string_start..];
    let (bs_len_size, bs_len) = parse_der_length(&bit_string[1..])?;
    let bs_content_start = 1 + bs_len_size;
    
    if bs_content_start + bs_len > bit_string.len() {
        return Err(anyhow!("Invalid DER: BIT STRING length mismatch"));
    }
    
    // Skip unused_bits byte (should be 0)
    let public_key_bytes = &bit_string[bs_content_start + 1..bs_content_start + bs_len];
    
    // Parse as P-384 public key (SEC1 encoded point)
    PublicKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| anyhow!("Failed to parse P-384 public key: {}", e))
}

/// Parse DER length encoding
/// Returns (bytes consumed, length value)
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(anyhow!("Empty data for DER length"));
    }
    
    if data[0] < 0x80 {
        // Short form
        Ok((1, data[0] as usize))
    } else if data[0] == 0x81 {
        // Long form, 1 byte
        if data.len() < 2 {
            return Err(anyhow!("Truncated DER length"));
        }
        Ok((2, data[1] as usize))
    } else if data[0] == 0x82 {
        // Long form, 2 bytes
        if data.len() < 3 {
            return Err(anyhow!("Truncated DER length"));
        }
        Ok((3, ((data[1] as usize) << 8) | (data[2] as usize)))
    } else {
        Err(anyhow!("Unsupported DER length encoding"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Key Generation Tests ====================

    #[test]
    fn test_generate_key() {
        let key = EncryptionKey::new();
        let pub_bytes = key.public_key_bytes();
        
        // P-384 uncompressed public key is 97 bytes (0x04 + 48 + 48)
        assert_eq!(pub_bytes.len(), 97);
        assert_eq!(pub_bytes[0], 0x04); // Uncompressed point prefix
        
        println!("P-384 Public Key: {}", key.public_key_hex());
    }

    #[test]
    fn test_generate_key_uniqueness() {
        // Each new() call should generate a different key
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        let key3 = EncryptionKey::new();
        
        assert_ne!(key1.public_key_bytes(), key2.public_key_bytes());
        assert_ne!(key2.public_key_bytes(), key3.public_key_bytes());
        assert_ne!(key1.public_key_bytes(), key3.public_key_bytes());
    }

    #[test]
    fn test_public_key_accessor() {
        let key = EncryptionKey::new();
        let pub_key = key.public_key();
        
        // Verify public key is valid by encoding it
        let encoded = pub_key.to_encoded_point(false);
        assert_eq!(encoded.as_bytes().len(), 97);
    }

    #[test]
    fn test_public_key_hex_format() {
        let key = EncryptionKey::new();
        let hex_str = key.public_key_hex();
        
        // Should start with 0x
        assert!(hex_str.starts_with("0x"));
        
        // Should be 0x + 194 hex chars (97 bytes * 2)
        assert_eq!(hex_str.len(), 2 + 194);
        
        // All chars after 0x should be valid hex
        assert!(hex_str[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ==================== Entropy-based Key Generation Tests ====================

    #[test]
    fn test_from_entropy() {
        let entropy = [0x42u8; 32];
        let key1 = EncryptionKey::from_entropy(&entropy).unwrap();
        let key2 = EncryptionKey::from_entropy(&entropy).unwrap();
        
        // Same entropy should produce same key
        assert_eq!(key1.public_key_bytes(), key2.public_key_bytes());
    }

    #[test]
    fn test_from_entropy_different_inputs() {
        let entropy1 = [0x00u8; 32];
        let entropy2 = [0xffu8; 32];
        let entropy3 = [0x42u8; 32];
        
        let key1 = EncryptionKey::from_entropy(&entropy1).unwrap();
        let key2 = EncryptionKey::from_entropy(&entropy2).unwrap();
        let key3 = EncryptionKey::from_entropy(&entropy3).unwrap();
        
        // Different entropy should produce different keys
        assert_ne!(key1.public_key_bytes(), key2.public_key_bytes());
        assert_ne!(key2.public_key_bytes(), key3.public_key_bytes());
        assert_ne!(key1.public_key_bytes(), key3.public_key_bytes());
    }

    #[test]
    fn test_from_entropy_short_input() {
        // Should work with less than 32 bytes (zero-padded)
        let short_entropy = [0xab, 0xcd, 0xef];
        let key = EncryptionKey::from_entropy(&short_entropy).unwrap();
        
        assert_eq!(key.public_key_bytes().len(), 97);
    }

    #[test]
    fn test_from_entropy_long_input() {
        // Should work with more than 32 bytes (truncated)
        let long_entropy = [0x42u8; 64];
        let key = EncryptionKey::from_entropy(&long_entropy).unwrap();
        
        assert_eq!(key.public_key_bytes().len(), 97);
        
        // Verify it only uses first 32 bytes
        let truncated_entropy = [0x42u8; 32];
        let key_truncated = EncryptionKey::from_entropy(&truncated_entropy).unwrap();
        assert_eq!(key.public_key_bytes(), key_truncated.public_key_bytes());
    }

    #[test]
    fn test_from_entropy_empty_input() {
        // Empty entropy should work (all zeros seed)
        let empty_entropy: [u8; 0] = [];
        let key = EncryptionKey::from_entropy(&empty_entropy).unwrap();
        
        assert_eq!(key.public_key_bytes().len(), 97);
    }

    // ==================== DER Encoding Tests ====================

    #[test]
    fn test_der_encoding() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        
        // DER should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
        
        // Should contain the P-384 OID (1.3.132.0.34)
        let oid_p384 = [0x2b, 0x81, 0x04, 0x00, 0x22];
        assert!(der.windows(oid_p384.len()).any(|w| w == oid_p384));
        
        println!("P-384 DER length: {} bytes", der.len());
        println!("P-384 DER: {}", hex::encode(&der));
    }

    #[test]
    fn test_der_encoding_contains_ec_oid() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        
        // Should contain the EC public key OID (1.2.840.10045.2.1)
        let oid_ec_pubkey = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        assert!(der.windows(oid_ec_pubkey.len()).any(|w| w == oid_ec_pubkey));
    }

    #[test]
    fn test_der_encoding_contains_public_key() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        let pub_bytes = key.public_key_bytes();
        
        // DER should contain the raw public key bytes
        assert!(der.windows(pub_bytes.len()).any(|w| w == pub_bytes.as_slice()));
    }

    #[test]
    fn test_der_encoding_consistent() {
        let key = EncryptionKey::new();
        let der1 = key.public_key_as_der().unwrap();
        let der2 = key.public_key_as_der().unwrap();
        
        // Same key should produce identical DER
        assert_eq!(der1, der2);
    }

    #[test]
    fn test_der_encoding_expected_length() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        
        // Expected SPKI structure size for P-384:
        // Outer SEQUENCE: 2 bytes tag+length (long form)
        // AlgorithmIdentifier: 2 + 9 + 7 = 18 bytes
        // BIT STRING: 3 (tag + long length) + 1 (unused bits) + 97 (key) = 101 bytes
        // Total: ~120 bytes (exact depends on length encoding)
        assert!(der.len() >= 115 && der.len() <= 125);
    }

    #[test]
    fn test_der_parse_roundtrip() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        
        // Parse the DER we generated
        let parsed = parse_der_public_key(&der).unwrap();
        
        // Should match original
        assert_eq!(key.public_key_bytes(), parsed.to_encoded_point(false).as_bytes().to_vec());
    }

    #[test]
    fn test_der_parse_multiple_keys() {
        // Verify DER roundtrip works for multiple different keys
        for _ in 0..5 {
            let key = EncryptionKey::new();
            let der = key.public_key_as_der().unwrap();
            let parsed = parse_der_public_key(&der).unwrap();
            assert_eq!(key.public_key_bytes(), parsed.to_encoded_point(false).as_bytes().to_vec());
        }
    }

    // ==================== DER Parsing Error Cases ====================

    #[test]
    fn test_der_parse_empty_input() {
        let result = parse_der_public_key(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_parse_invalid_tag() {
        // Not starting with SEQUENCE (0x30)
        let invalid = [0x31, 0x00];
        let result = parse_der_public_key(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_parse_truncated_data() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        
        // Truncate to various lengths
        for len in [1, 2, 10, 50, der.len() - 1] {
            let truncated = &der[..len.min(der.len())];
            let result = parse_der_public_key(truncated);
            assert!(result.is_err(), "Should fail with {} bytes", len);
        }
    }

    #[test]
    fn test_der_parse_corrupted_public_key() {
        let key = EncryptionKey::new();
        let mut der = key.public_key_as_der().unwrap();
        
        // Corrupt the public key bytes near the end (changes EC point)
        let len = der.len();
        der[len - 10] ^= 0xff; // XOR to corrupt while keeping length valid
        der[len - 5] ^= 0xff;
        
        // Parsing should fail because the corrupted bytes don't form a valid EC point
        let result = parse_der_public_key(&der);
        assert!(result.is_err());
    }

    // ==================== parse_der_length Tests ====================

    #[test]
    fn test_parse_der_length_short_form() {
        // Values 0-127 use short form
        let data = [0x42];
        let (bytes_consumed, length) = parse_der_length(&data).unwrap();
        assert_eq!(bytes_consumed, 1);
        assert_eq!(length, 0x42);
    }

    #[test]
    fn test_parse_der_length_long_form_one_byte() {
        // 0x81 prefix for 1-byte length
        let data = [0x81, 0x80];
        let (bytes_consumed, length) = parse_der_length(&data).unwrap();
        assert_eq!(bytes_consumed, 2);
        assert_eq!(length, 128);
    }

    #[test]
    fn test_parse_der_length_long_form_two_bytes() {
        // 0x82 prefix for 2-byte length
        let data = [0x82, 0x01, 0x00];
        let (bytes_consumed, length) = parse_der_length(&data).unwrap();
        assert_eq!(bytes_consumed, 3);
        assert_eq!(length, 256);
    }

    #[test]
    fn test_parse_der_length_empty_data() {
        let result = parse_der_length(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_length_truncated_long_form() {
        // 0x81 but no length byte follows
        let result = parse_der_length(&[0x81]);
        assert!(result.is_err());
        
        // 0x82 but only one length byte
        let result = parse_der_length(&[0x82, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_length_unsupported_encoding() {
        // 0x83 would be 3-byte length, currently unsupported
        let result = parse_der_length(&[0x83, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    // ==================== Encryption/Decryption Tests ====================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create two key pairs (simulating enclave and client)
        let enclave_key = EncryptionKey::new();
        let client_key = EncryptionKey::new();
        
        // Get DER-encoded public keys
        let enclave_pub_der = enclave_key.public_key_as_der().unwrap();
        let client_pub_der = client_key.public_key_as_der().unwrap();
        
        // Client encrypts data to enclave
        let plaintext = b"Hello, Enclave!";
        let nonce = [0x42u8; 12];
        let ciphertext = client_key.encrypt(plaintext, &enclave_pub_der, &nonce).unwrap();
        
        // Enclave decrypts data from client
        let decrypted = enclave_key.decrypt(&nonce, &client_pub_der, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bidirectional() {
        let party_a = EncryptionKey::new();
        let party_b = EncryptionKey::new();
        
        let a_pub_der = party_a.public_key_as_der().unwrap();
        let b_pub_der = party_b.public_key_as_der().unwrap();
        
        // A sends message to B
        let msg_a_to_b = b"Message from A to B";
        let nonce1 = [0x01u8; 12];
        let ciphertext1 = party_a.encrypt(msg_a_to_b, &b_pub_der, &nonce1).unwrap();
        let decrypted1 = party_b.decrypt(&nonce1, &a_pub_der, &ciphertext1).unwrap();
        assert_eq!(decrypted1, msg_a_to_b);
        
        // B sends message to A
        let msg_b_to_a = b"Message from B to A";
        let nonce2 = [0x02u8; 12];
        let ciphertext2 = party_b.encrypt(msg_b_to_a, &a_pub_der, &nonce2).unwrap();
        let decrypted2 = party_a.decrypt(&nonce2, &b_pub_der, &ciphertext2).unwrap();
        assert_eq!(decrypted2, msg_b_to_a);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext: &[u8] = b"";
        let nonce = [0x00u8; 12];
        
        let ciphertext = key1.encrypt(plaintext, &pub2_der, &nonce).unwrap();
        let decrypted = key2.decrypt(&nonce, &pub1_der, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_plaintext() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        // 1MB of data
        let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        let nonce = [0xabu8; 12];
        
        let ciphertext = key1.encrypt(&plaintext, &pub2_der, &nonce).unwrap();
        let decrypted = key2.decrypt(&nonce, &pub1_der, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_32_byte_nonce() {
        // API accepts 32-byte nonce, uses first 12 bytes
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Testing 32-byte nonce";
        let nonce_32 = [0xffu8; 32];
        
        let ciphertext = key1.encrypt(plaintext, &pub2_der, &nonce_32).unwrap();
        let decrypted = key2.decrypt(&nonce_32, &pub1_der, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_nonce_prefix_matters() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let _pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Test nonce prefix";
        
        // Two nonces that differ only in bytes 12+ should produce same result
        let nonce_a = [0x42u8; 32];
        let mut nonce_b = [0x42u8; 32];
        nonce_b[12..].fill(0xff); // Change only bytes after first 12
        
        let ciphertext_a = key1.encrypt(plaintext, &pub2_der, &nonce_a).unwrap();
        let ciphertext_b = key1.encrypt(plaintext, &pub2_der, &nonce_b).unwrap();
        
        // Should produce same ciphertext since first 12 bytes are identical
        assert_eq!(ciphertext_a, ciphertext_b);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext_with_different_nonces() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Same plaintext";
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];
        
        let ciphertext1 = key1.encrypt(plaintext, &pub2_der, &nonce1).unwrap();
        let ciphertext2 = key1.encrypt(plaintext, &pub2_der, &nonce2).unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_ciphertext_includes_auth_tag() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Test";
        let nonce = [0x00u8; 12];
        
        let ciphertext = key1.encrypt(plaintext, &pub2_der, &nonce).unwrap();
        
        // AES-GCM adds 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    // ==================== Encryption Error Cases ====================

    #[test]
    fn test_encrypt_short_nonce() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub2_der = key2.public_key_as_der().unwrap();
        let plaintext = b"Test";
        let short_nonce = [0x00u8; 8]; // Less than 12 bytes
        
        let result = key1.encrypt(plaintext, &pub2_der, &short_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_nonce() {
        let key1 = EncryptionKey::new();
        let short_nonce = [0x00u8; 8]; // Less than 12 bytes
        let fake_ciphertext = [0x00u8; 32];
        
        // Create a valid DER for peer key
        let key2 = EncryptionKey::new();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let result = key1.decrypt(&short_nonce, &pub2_der, &fake_ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_invalid_peer_public_key() {
        let key1 = EncryptionKey::new();
        let plaintext = b"Test";
        let nonce = [0x00u8; 12];
        let invalid_der = [0x30, 0x00]; // Invalid/empty SPKI
        
        let result = key1.encrypt(plaintext, &invalid_der, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_peer_public_key() {
        let key1 = EncryptionKey::new();
        let nonce = [0x00u8; 12];
        let ciphertext = [0x00u8; 32];
        let invalid_der = [0x30, 0x00]; // Invalid/empty SPKI
        
        let result = key1.decrypt(&nonce, &invalid_der, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Sensitive data";
        let nonce = [0x42u8; 12];
        
        let mut ciphertext = key1.encrypt(plaintext, &pub2_der, &nonce).unwrap();
        
        // Tamper with ciphertext
        ciphertext[0] ^= 0xff;
        
        // Decryption should fail due to authentication failure
        let result = key2.decrypt(&nonce, &pub1_der, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_nonce() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Test data";
        let nonce = [0x42u8; 12];
        let wrong_nonce = [0x00u8; 12];
        
        let ciphertext = key1.encrypt(plaintext, &pub2_der, &nonce).unwrap();
        
        // Decryption with wrong nonce should fail
        let result = key2.decrypt(&wrong_nonce, &pub1_der, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        let key3 = EncryptionKey::new(); // Third party
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let plaintext = b"Secret message";
        let nonce = [0x42u8; 12];
        
        // Key1 encrypts for Key2
        let ciphertext = key1.encrypt(plaintext, &pub2_der, &nonce).unwrap();
        
        // Key3 (wrong recipient) tries to decrypt
        let result = key3.decrypt(&nonce, &pub1_der, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_empty_ciphertext() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub2_der = key2.public_key_as_der().unwrap();
        let nonce = [0x00u8; 12];
        
        // Empty ciphertext (no auth tag)
        let result = key1.decrypt(&nonce, &pub2_der, &[]);
        assert!(result.is_err());
    }

    // ==================== ECDH Shared Key Derivation Tests ====================

    #[test]
    fn test_ecdh_shared_secret_symmetric() {
        // ECDH should produce same shared secret regardless of direction
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        // If we encrypt with key1->key2 and key2->key1, using same nonce,
        // the derived keys should be the same, so ciphertexts should match
        let plaintext = b"Test symmetry";
        let nonce = [0x42u8; 12];
        
        let ct1 = key1.encrypt(plaintext, &pub2_der, &nonce).unwrap();
        let ct2 = key2.encrypt(plaintext, &pub1_der, &nonce).unwrap();
        
        // Same shared key, same plaintext, same nonce = same ciphertext
        assert_eq!(ct1, ct2);
    }

    // ==================== Multiple Operations Tests ====================

    #[test]
    fn test_multiple_messages_same_keys() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        // Send multiple messages with different nonces
        for i in 0..10u8 {
            let plaintext = format!("Message number {}", i);
            let mut nonce = [0u8; 12];
            nonce[0] = i;
            
            let ciphertext = key1.encrypt(plaintext.as_bytes(), &pub2_der, &nonce).unwrap();
            let decrypted = key2.decrypt(&nonce, &pub1_der, &ciphertext).unwrap();
            
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[test]
    fn test_various_plaintext_sizes() {
        let key1 = EncryptionKey::new();
        let key2 = EncryptionKey::new();
        
        let pub1_der = key1.public_key_as_der().unwrap();
        let pub2_der = key2.public_key_as_der().unwrap();
        
        let sizes = [0, 1, 15, 16, 17, 31, 32, 33, 127, 128, 255, 256, 1000, 4096];
        
        for size in sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let mut nonce = [0u8; 12];
            nonce[0] = (size % 256) as u8;
            
            let ciphertext = key1.encrypt(&plaintext, &pub2_der, &nonce).unwrap();
            let decrypted = key2.decrypt(&nonce, &pub1_der, &ciphertext).unwrap();
            
            assert_eq!(decrypted, plaintext, "Failed for size {}", size);
        }
    }
}

