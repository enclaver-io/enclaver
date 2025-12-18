use anyhow::Result;
use p384::ecdh::EphemeralSecret;
use p384::PublicKey;
use rand::rngs::OsRng;

/// P-384 encryption key pair for attestation
/// Used for ECDH key exchange to encrypt data to the enclave
pub struct EncryptionKey {
    secret: EphemeralSecret,
    public_key: PublicKey,
}

impl EncryptionKey {
    /// Generate new P-384 key pair
    pub fn new() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = secret.public_key();
        Self { secret, public_key }
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
        let secret = EphemeralSecret::random(&mut rng);
        let public_key = secret.public_key();
        Ok(Self { secret, public_key })
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Raw SEC1-encoded uncompressed public key (97 bytes: 0x04 + 96 bytes)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
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
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        
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

    /// Get the ephemeral secret for ECDH operations
    pub fn secret(&self) -> &EphemeralSecret {
        &self.secret
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
}
