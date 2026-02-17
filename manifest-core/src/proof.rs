use serde::{Deserialize, Serialize};

/// A third-party countersignature over a receipt, providing independent
/// attestation (e.g., from a Cloud Vault timestamping authority).
///
/// This field is reserved for future use. The open-source CLI always sets
/// `countersignatures` to `None`. When a Cloud Vault or third-party service
/// co-signs a receipt, it appends a `Countersignature` entry here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Countersignature {
    /// Identity of the countersigner (e.g., "https://vault.portauthority.dev").
    pub signer: String,

    /// Signing algorithm used (e.g., "ed25519").
    pub algorithm: String,

    /// The countersignature value (e.g., "ed25519:<base64>").
    pub signature: String,

    /// ISO 8601 timestamp when the countersignature was created.
    pub timestamp: String,
}

/// Cryptographic proof binding all receipt fields together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Ed25519 signature over the canonical receipt bytes: `"ed25519:<base64>"`.
    pub signature: String,

    /// Current Merkle tree root after appending this receipt: `"sha256:<hex>"`.
    #[serde(rename = "merkleRoot")]
    pub merkle_root: String,

    /// Content hash of the previous receipt in the chain: `"sha256:<hex>"`.
    /// None for the first receipt in a session.
    #[serde(rename = "previousReceipt", skip_serializing_if = "Option::is_none")]
    pub previous_receipt: Option<String>,

    /// Third-party countersignatures for independent attestation.
    /// Reserved for future Cloud Vault integration. Always `None` in the
    /// open-source CLI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub countersignatures: Option<Vec<Countersignature>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_without_countersignatures_omits_field() {
        let proof = Proof {
            signature: "ed25519:abc".into(),
            merkle_root: "sha256:def".into(),
            previous_receipt: None,
            countersignatures: None,
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains("countersignatures"));
        assert!(!json.contains("previousReceipt"));
    }

    #[test]
    fn proof_with_countersignatures_roundtrips() {
        let proof = Proof {
            signature: "ed25519:abc".into(),
            merkle_root: "sha256:def".into(),
            previous_receipt: Some("sha256:prev".into()),
            countersignatures: Some(vec![Countersignature {
                signer: "https://vault.portauthority.dev".into(),
                algorithm: "ed25519".into(),
                signature: "ed25519:cosig123".into(),
                timestamp: "2026-02-17T00:00:00Z".into(),
            }]),
        };

        let json = serde_json::to_string_pretty(&proof).unwrap();
        assert!(json.contains("countersignatures"));
        assert!(json.contains("vault.portauthority.dev"));

        let deserialized: Proof = serde_json::from_str(&json).unwrap();
        let cosigs = deserialized.countersignatures.unwrap();
        assert_eq!(cosigs.len(), 1);
        assert_eq!(cosigs[0].signer, "https://vault.portauthority.dev");
        assert_eq!(cosigs[0].algorithm, "ed25519");
        assert_eq!(cosigs[0].signature, "ed25519:cosig123");
        assert_eq!(cosigs[0].timestamp, "2026-02-17T00:00:00Z");
    }

    #[test]
    fn proof_without_countersignatures_deserializes_from_old_format() {
        // Receipts generated before the countersignatures field existed
        // should still deserialize correctly (field is None).
        let old_json = r#"{
            "signature": "ed25519:old",
            "merkleRoot": "sha256:old",
            "previousReceipt": "sha256:prev"
        }"#;
        let proof: Proof = serde_json::from_str(old_json).unwrap();
        assert!(proof.countersignatures.is_none());
        assert_eq!(proof.signature, "ed25519:old");
    }
}
