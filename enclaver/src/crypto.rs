use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::keccak256;

    #[test]
    fn keccak256_is_deterministic() {
        let data = b"enclaver-keccak";
        assert_eq!(keccak256(data), keccak256(data));
    }

    #[test]
    fn keccak256_changes_when_input_changes() {
        assert_ne!(keccak256(b"a"), keccak256(b"b"));
    }
}
