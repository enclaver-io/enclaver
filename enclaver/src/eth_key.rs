use anyhow::{Result, anyhow};
use hex;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

pub struct EthKey {
    // k256::ecdsa::SigningKey zeroizes on drop via ZeroizeOnDrop.
    signing_key: SigningKey,
    verify_key: VerifyingKey,
}

impl EthKey {
    /// generate new key
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verify_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verify_key,
        }
    }

    /// build from explicit entropy
    pub fn from_entropy(entropy: [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(&entropy.into())
            .map_err(|e| anyhow!("invalid secp256k1 key from entropy: {:?}", e))?;
        let verify_key = VerifyingKey::from(&signing_key);
        Ok(Self {
            signing_key,
            verify_key,
        })
    }

    /// import key from hex
    pub fn new_from_bytes(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
            .map_err(|e| format!("Invalid hex: {}", e))?;

        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Private key must be 32 bytes".to_string())?;

        let signing_key = SigningKey::from_bytes(&arr.into())
            .map_err(|e| format!("Invalid private key: {:?}", e))?;
        let verify_key = VerifyingKey::from(&signing_key);
        Ok(Self {
            signing_key,
            verify_key,
        })
    }

    pub(crate) fn private_key_hex_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("0x{}", hex::encode(self.signing_key.to_bytes())))
    }

    #[cfg(test)]
    fn private_key_hex_for_test(&self) -> String {
        self.private_key_hex_zeroizing().to_string()
    }

    /// uncompressed public key
    pub fn public_key_hex(&self) -> String {
        format!(
            "0x{}",
            hex::encode(self.verify_key.to_encoded_point(false).as_bytes())
        )
    }

    /// Ethereum address
    pub fn address(&self) -> String {
        let pub_bytes = self.verify_key.to_encoded_point(false);
        let hash = crate::crypto::keccak256(&pub_bytes.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    /// Ethereum address as raw 20 bytes (for attestation user_data)
    pub fn address_bytes(&self) -> Vec<u8> {
        let pub_bytes = self.verify_key.to_encoded_point(false);
        let hash = crate::crypto::keccak256(&pub_bytes.as_bytes()[1..]);
        hash[12..].to_vec()
    }

    /// Raw SEC1-encoded uncompressed public key (65 bytes: 0x04 + 64 bytes)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verify_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// DER-encoded SubjectPublicKeyInfo for NSM attestation
    /// Constructs a DER-encoded SPKI with secp256k1 OID
    ///
    /// Structure:
    /// SubjectPublicKeyInfo ::= SEQUENCE {
    ///   algorithm AlgorithmIdentifier,
    ///   subjectPublicKey BIT STRING
    /// }
    /// AlgorithmIdentifier ::= SEQUENCE {
    ///   algorithm OBJECT IDENTIFIER,  -- 1.2.840.10045.2.1 (EC public key)
    ///   parameters OBJECT IDENTIFIER   -- 1.3.132.0.10 (secp256k1)
    /// }
    pub fn public_key_as_der(&self) -> Result<Vec<u8>> {
        // OID encodings:
        // 1.2.840.10045.2.1 (EC public key) = 06 07 2a 86 48 ce 3d 02 01
        // 1.3.132.0.10 (secp256k1) = 06 05 2b 81 04 00 0a
        let oid_ec_pubkey: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let oid_secp256k1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];

        // Get SEC1-encoded uncompressed public key (65 bytes: 0x04 + 64 bytes)
        let encoded_point = self.verify_key.to_encoded_point(false);
        let pub_key_bytes = encoded_point.as_bytes();

        // AlgorithmIdentifier SEQUENCE: algorithm OID + parameters OID
        let alg_seq_len = oid_ec_pubkey.len() + oid_secp256k1.len();
        let alg_seq = {
            let mut seq = Vec::with_capacity(2 + alg_seq_len);
            seq.push(0x30); // SEQUENCE tag
            seq.push(alg_seq_len as u8);
            seq.extend_from_slice(oid_ec_pubkey);
            seq.extend_from_slice(oid_secp256k1);
            seq
        };

        // BitString: unused_bits (1 byte) + public key bytes
        let bit_string_len = 1 + pub_key_bytes.len();
        let bit_string = {
            let mut bs = Vec::with_capacity(2 + bit_string_len);
            bs.push(0x03); // BIT STRING tag
            bs.push(bit_string_len as u8);
            bs.push(0x00); // unused_bits = 0
            bs.extend_from_slice(pub_key_bytes);
            bs
        };

        // SubjectPublicKeyInfo SEQUENCE: AlgorithmIdentifier + BitString
        let spki_len = alg_seq.len() + bit_string.len();
        let mut spki = Vec::with_capacity(2 + spki_len);
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

    pub fn sign_message(&self, message: &[u8]) -> [u8; 65] {
        let digest = Keccak256::new_with_prefix(message);
        let (sig, recid) = self
            .signing_key
            .sign_digest_recoverable(digest.clone())
            .unwrap();
        let mut result = [0u8; 65];
        result[..64].copy_from_slice(sig.to_bytes().as_ref());
        result[64] = recid.to_byte();
        result
    }

    pub fn verify_message(sig_hex: String, message: &[u8], address: String) -> bool {
        let sig_bytes: Vec<u8> = match hex::decode(sig_hex.strip_prefix("0x").unwrap_or(&sig_hex)) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if sig_bytes.len() != 65 {
            return false;
        }
        let digest = Keccak256::new_with_prefix(message);
        let r_s = &sig_bytes[..64];
        let sig = match Signature::from_bytes(r_s.into()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let recid = match RecoveryId::from_byte(sig_bytes[64]) {
            Some(v) => v,
            None => return false,
        };
        let verifying_key = match VerifyingKey::recover_from_digest(digest.clone(), &sig, recid) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let pub_bytes = verifying_key.to_encoded_point(false);
        let hash = crate::crypto::keccak256(&pub_bytes.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..])) == address.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_address() {
        let key = EthKey::new();
        println!("Private Key: {}", key.private_key_hex_for_test());
        println!("Public Key: {}", key.public_key_hex());
        println!("Address: {}", key.address());

        assert_eq!(key.private_key_hex_for_test().len(), 66);
        assert_eq!(key.public_key_hex().len(), 132);
        assert_eq!(key.address().len(), 42);
    }

    #[test]
    fn test_from_and_address() {
        let pk = "0x2151833c4e545b28d64d87ed80dcc735a14d70f537e8885b227a5dbe7994da26";
        let key = EthKey::new_from_bytes(pk).unwrap();
        println!("Private Key: {}", key.private_key_hex_for_test());
        println!("Public Key: {}", key.public_key_hex());
        println!("Address: {}", key.address());

        assert_eq!(
            key.private_key_hex_for_test(),
            "0x2151833c4e545b28d64d87ed80dcc735a14d70f537e8885b227a5dbe7994da26"
        );
        assert_eq!(
            key.public_key_hex(),
            "0x047df31522e92da43df5e709bbae0a5c3cb9cf746973cf98eae0f7bdd865809a5c91a2df421125debc451cdd0a41791f333fced9d69f9eeb14bfdbacbff9a7ccb1"
        );
        assert_eq!(key.address(), "0xd30077d0ee91bc6907a1666f1d2054b4322a2b0f");
    }

    #[test]
    fn test_sign_verify() {
        let message = "Hello, Ethereum!";
        let pk = "0x2151833c4e545b28d64d87ed80dcc735a14d70f537e8885b227a5dbe7994da26";
        let key = EthKey::new_from_bytes(pk).unwrap();

        let sig = key.sign_message(message.as_bytes());
        let sig_hex = format!("0x{}", hex::encode(sig));
        println!("Signature: {}", sig_hex);

        let verified = EthKey::verify_message(sig_hex, message.as_bytes(), key.address());
        println!("verified: {}", verified);
    }

    #[test]
    fn test_verify_message_rejects_invalid_hex_without_panic() {
        let verified = EthKey::verify_message(
            "0x-not-hex".to_string(),
            b"message",
            "0x0000000000000000000000000000000000000000".to_string(),
        );
        assert!(!verified);
    }

    #[test]
    fn test_verify_message_rejects_wrong_length_without_panic() {
        let verified = EthKey::verify_message(
            "0x1234".to_string(),
            b"message",
            "0x0000000000000000000000000000000000000000".to_string(),
        );
        assert!(!verified);
    }
}
