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
