use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::action::Action;
use crate::error::ManifestError;
use crate::hashing::sha256_hex;
use crate::identity::AgentIdentity;
use crate::merkle::MerkleTree;
use crate::policy::PolicySnapshot;
use crate::proof::Proof;
use crate::signing::Signer;

/// Authorization delta: was the action authorized, and what violations occurred?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    pub authorized: bool,
    pub violations: Vec<String>,
}

/// A cryptographic receipt for a single tool call.
///
/// Each receipt is a self-contained, tamper-proof record linking what the agent
/// did to what it was authorized to do. Serialized as JSON-LD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(rename = "@context")]
    pub context: String,

    pub id: String,

    pub timestamp: DateTime<Utc>,

    pub agent: AgentIdentity,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySnapshot>,

    pub action: Action,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta>,

    pub proof: Proof,
}

impl Receipt {
    /// Compute the canonical bytes for signing.
    ///
    /// Includes all fields except `proof.signature` and `proof.merkle_root`
    /// to avoid circular dependencies (the root depends on the receipt hash,
    /// which depends on the signature).
    ///
    /// Uses `serde_json::to_vec` on a `Value` object, which produces sorted
    /// keys via `BTreeMap` (default serde_json without `preserve_order`).
    /// This guarantees cross-platform deterministic serialization.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let signable = serde_json::json!({
            "@context": self.context,
            "id": self.id,
            "timestamp": self.timestamp,
            "agent": self.agent,
            "policy": self.policy,
            "action": self.action,
            "delta": self.delta,
            "previousReceipt": self.proof.previous_receipt,
        });
        serde_json::to_vec(&signable).unwrap_or_default()
    }

    /// Compute the SHA-256 content hash of this receipt (post-signing, pre-Merkle).
    ///
    /// Covers identity + policy + action + delta + signature + previousReceipt.
    /// The merkle_root is excluded because it depends on this hash.
    ///
    /// Canonical JSON: sorted keys via `BTreeMap`-backed `Value` objects.
    pub fn content_hash(&self) -> String {
        let hashable = serde_json::json!({
            "@context": self.context,
            "id": self.id,
            "timestamp": self.timestamp,
            "agent": self.agent,
            "policy": self.policy,
            "action": self.action,
            "delta": self.delta,
            "signature": self.proof.signature,
            "previousReceipt": self.proof.previous_receipt,
        });
        let bytes = serde_json::to_vec(&hashable).unwrap_or_default();
        sha256_hex(&bytes)
    }
}

/// Builder for constructing and signing receipts.
pub struct ReceiptBuilder {
    agent: Option<AgentIdentity>,
    policy: Option<PolicySnapshot>,
    action: Option<Action>,
    delta: Option<Delta>,
    previous_receipt: Option<String>,
}

impl ReceiptBuilder {
    pub fn new() -> Self {
        Self {
            agent: None,
            policy: None,
            action: None,
            delta: None,
            previous_receipt: None,
        }
    }

    pub fn agent(mut self, agent: AgentIdentity) -> Self {
        self.agent = Some(agent);
        self
    }

    pub fn policy(mut self, policy: Option<PolicySnapshot>) -> Self {
        self.policy = policy;
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    pub fn delta(mut self, delta: Option<Delta>) -> Self {
        self.delta = delta;
        self
    }

    pub fn previous_receipt(mut self, hash: Option<String>) -> Self {
        self.previous_receipt = hash;
        self
    }

    /// Build, sign, and chain the receipt into the Merkle tree.
    ///
    /// Flow:
    /// 1. Assemble all fields with placeholder proof
    /// 2. Compute canonical bytes and sign
    /// 3. Compute content hash (includes signature)
    /// 4. Append to Merkle tree and set the root
    pub fn build(
        self,
        signer: &Signer,
        merkle: &mut MerkleTree,
    ) -> Result<Receipt, ManifestError> {
        let agent = self
            .agent
            .ok_or_else(|| ManifestError::Config("receipt requires agent identity".into()))?;
        let action = self
            .action
            .ok_or_else(|| ManifestError::Config("receipt requires action".into()))?;

        // Step 1: Assemble with placeholder proof
        let mut receipt = Receipt {
            context: "https://portauthority.dev/receipt/v1".to_string(),
            id: format!("urn:uuid:{}", Uuid::now_v7()),
            timestamp: Utc::now(),
            agent,
            policy: self.policy,
            action,
            delta: self.delta,
            proof: Proof {
                signature: String::new(),
                merkle_root: String::new(),
                previous_receipt: self.previous_receipt,
            },
        };

        // Step 2: Sign the canonical bytes
        let canonical = receipt.canonical_bytes();
        receipt.proof.signature = signer.sign(&canonical);

        // Step 3: Compute content hash (covers signature)
        let content_hash = receipt.content_hash();

        // Step 4: Append to Merkle tree
        let hash_bytes: [u8; 32] = hex::decode(
            content_hash
                .strip_prefix("sha256:")
                .unwrap_or(&content_hash),
        )
        .map_err(|e| ManifestError::Signing(format!("invalid hash hex: {e}")))?
        .try_into()
        .map_err(|_| ManifestError::Signing("hash is not 32 bytes".into()))?;

        merkle.append(hash_bytes);
        receipt.proof.merkle_root = merkle.root();

        Ok(receipt)
    }
}

impl Default for ReceiptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentitySource;

    fn test_identity() -> AgentIdentity {
        AgentIdentity {
            name: "test-agent".to_string(),
            version: Some("1.0".to_string()),
            deployer: None,
            environment: None,
            source: IdentitySource::Environment,
            verified: false,
        }
    }

    fn test_action() -> Action {
        Action {
            tool: "db_query".to_string(),
            input: serde_json::json!({"query": "SELECT 1"}),
            output: Some(serde_json::json!({"rows": 1})),
            error: None,
        }
    }

    #[test]
    fn build_receipt() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .build(&signer, &mut merkle)
            .unwrap();

        assert_eq!(receipt.context, "https://portauthority.dev/receipt/v1");
        assert!(receipt.id.starts_with("urn:uuid:"));
        assert!(receipt.proof.signature.starts_with("ed25519:"));
        assert!(receipt.proof.merkle_root.starts_with("sha256:"));
        assert!(receipt.proof.previous_receipt.is_none());
        assert_eq!(merkle.len(), 1);
    }

    #[test]
    fn receipt_chaining() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let r1 = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .build(&signer, &mut merkle)
            .unwrap();

        let r1_hash = r1.content_hash();

        let r2 = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .previous_receipt(Some(r1_hash.clone()))
            .build(&signer, &mut merkle)
            .unwrap();

        assert_eq!(r2.proof.previous_receipt.as_deref(), Some(r1_hash.as_str()));
        assert_eq!(merkle.len(), 2);
        // Merkle roots should differ
        assert_ne!(r1.proof.merkle_root, r2.proof.merkle_root);
    }

    #[test]
    fn signature_is_verifiable() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .build(&signer, &mut merkle)
            .unwrap();

        let canonical = receipt.canonical_bytes();
        assert!(signer.verify(&canonical, &receipt.proof.signature).unwrap());
    }

    #[test]
    fn receipt_serializes_to_json_ld() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .build(&signer, &mut merkle)
            .unwrap();

        let json = serde_json::to_value(&receipt).unwrap();
        assert_eq!(json["@context"], "https://portauthority.dev/receipt/v1");
        assert!(json["id"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(json["action"]["tool"], "db_query");
        assert!(json["proof"]["merkleRoot"].as_str().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn content_hash_is_deterministic() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .build(&signer, &mut merkle)
            .unwrap();

        assert_eq!(receipt.content_hash(), receipt.content_hash());
    }

    #[test]
    fn build_fails_without_agent() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let result = ReceiptBuilder::new()
            .action(test_action())
            .build(&signer, &mut merkle);

        assert!(result.is_err());
    }

    #[test]
    fn canonical_bytes_have_sorted_keys() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(test_identity())
            .action(test_action())
            .build(&signer, &mut merkle)
            .unwrap();

        let canonical = receipt.canonical_bytes();
        let json_str = String::from_utf8(canonical).unwrap();

        // Parse back and verify keys are alphabetically sorted at top level
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let obj = parsed.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "canonical JSON keys must be sorted");
    }

    #[test]
    fn build_fails_without_action() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let result = ReceiptBuilder::new()
            .agent(test_identity())
            .build(&signer, &mut merkle);

        assert!(result.is_err());
    }
}
