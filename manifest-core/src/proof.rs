use serde::{Deserialize, Serialize};

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
}
