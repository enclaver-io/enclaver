use anyhow::{Result, anyhow};
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
    fn test_from_entropy() {
        let entropy = [0x42u8; 32];
        let key1 = EncryptionKey::from_entropy(&entropy).unwrap();
        let key2 = EncryptionKey::from_entropy(&entropy).unwrap();
        
        // Same entropy should produce same key
        assert_eq!(key1.public_key_bytes(), key2.public_key_bytes());
    }

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
    fn test_der_parse_roundtrip() {
        let key = EncryptionKey::new();
        let der = key.public_key_as_der().unwrap();
        
        // Parse the DER we generated
        let parsed = parse_der_public_key(&der).unwrap();
        
        // Should match original
        assert_eq!(key.public_key_bytes(), parsed.to_encoded_point(false).as_bytes().to_vec());
    }
}

