use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::ManifestError;

/// Ed25519 signer for receipt cryptographic sealing.
///
/// Wraps an Ed25519 signing key and provides sign/verify operations
/// that produce `"ed25519:<base64>"` formatted signature strings.
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load a signing key from a 32-byte seed file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ManifestError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(ManifestError::Signing(format!(
                "key file must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let seed: [u8; 32] = bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    /// Save the 32-byte seed to a file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), ManifestError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.signing_key.to_bytes())?;
        Ok(())
    }

    /// Sign arbitrary bytes. Returns `"ed25519:<base64>"`.
    pub fn sign(&self, data: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(data);
        format!(
            "ed25519:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes())
        )
    }

    /// Verify a signature string (`"ed25519:<base64>"`) against data.
    pub fn verify(&self, data: &[u8], signature_str: &str) -> Result<bool, ManifestError> {
        let encoded = signature_str
            .strip_prefix("ed25519:")
            .ok_or_else(|| ManifestError::Signing("signature must start with 'ed25519:'".into()))?;

        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|e| ManifestError::Signing(format!("invalid base64: {e}")))?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| ManifestError::Signing(format!("invalid signature bytes: {e}")))?;

        let verifying_key = self.signing_key.verifying_key();
        Ok(verifying_key.verify(data, &signature).is_ok())
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Signer::generate();
        let data = b"test data for signing";
        let sig = signer.sign(data);

        assert!(sig.starts_with("ed25519:"));
        assert!(signer.verify(data, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_data() {
        let signer = Signer::generate();
        let sig = signer.sign(b"original");
        assert!(!signer.verify(b"tampered", &sig).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let data = b"test";
        let sig = signer1.sign(data);

        // signer2 can't verify signer1's signature
        assert!(!signer2.verify(data, &sig).unwrap());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");

        let signer = Signer::generate();
        let data = b"persistence test";
        let sig = signer.sign(data);

        signer.save(&path).unwrap();
        let loaded = Signer::from_file(&path).unwrap();

        assert!(loaded.verify(data, &sig).unwrap());
    }

    #[test]
    fn rejects_invalid_key_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, b"too short").unwrap();

        assert!(Signer::from_file(&path).is_err());
    }
}
