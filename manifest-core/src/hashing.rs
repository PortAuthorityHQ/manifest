use sha2::{Digest, Sha256};

/// Compute the SHA-256 hash of arbitrary bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 and return as a prefixed hex string: `"sha256:<hex>"`.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    format!("sha256:{}", hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of empty string
        let hash = sha256(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_format() {
        let result = sha256_hex(b"hello");
        assert!(result.starts_with("sha256:"));
        assert_eq!(result.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn sha256_deterministic() {
        let a = sha256(b"manifest");
        let b = sha256(b"manifest");
        assert_eq!(a, b);
    }
}
