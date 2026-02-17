use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use manifest_core::{
    Action, ActionError, MerkleTree, ReceiptBuilder, Signer, Storage,
};
use tokio::sync::mpsc;

use crate::session::McpSession;

/// A captured tool call ready for receipt generation.
pub struct CapturedToolCall {
    pub tool_name: String,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub error: Option<ActionError>,
    pub timestamp: DateTime<Utc>,
}

/// Background worker that consumes captured tool calls and generates signed receipts.
///
/// Runs as a `tokio::spawn`-ed task. Reads from the mpsc channel and for each
/// captured call: builds the receipt, signs it, appends to the Merkle tree,
/// and persists to SQLite. Errors are logged but never propagated — the relay
/// must never be blocked or disrupted by receipt generation failures.
pub async fn receipt_worker(
    mut rx: mpsc::UnboundedReceiver<CapturedToolCall>,
    session: Arc<Mutex<McpSession>>,
    signer: Arc<Signer>,
    merkle: Arc<Mutex<MerkleTree>>,
    storage: Arc<Mutex<Storage>>,
) {
    while let Some(captured) = rx.recv().await {
        if let Err(e) = process_captured_call(&captured, &session, &signer, &merkle, &storage) {
            tracing::error!(
                tool = %captured.tool_name,
                error = %e,
                "failed to generate receipt"
            );
        }
    }

    tracing::debug!("receipt worker shutting down");
}

fn process_captured_call(
    captured: &CapturedToolCall,
    session: &Arc<Mutex<McpSession>>,
    signer: &Signer,
    merkle: &Arc<Mutex<MerkleTree>>,
    storage: &Arc<Mutex<Storage>>,
) -> Result<(), manifest_core::ManifestError> {
    let (identity, policy_snapshot, session_id, delta) = {
        let sess = session.lock().map_err(|e| {
            manifest_core::ManifestError::Config(format!("session lock poisoned: {e}"))
        })?;

        let identity = sess.identity();
        let policy_snapshot = sess.policy_snapshot();
        let session_id = sess.session_id.clone();

        // Check authorization
        let (authorized, violations) = sess.check_tool(&captured.tool_name);
        let delta = if sess.policy_snapshot().is_some() {
            Some(manifest_core::receipt::Delta {
                authorized,
                violations,
            })
        } else {
            None
        };

        (identity, policy_snapshot, session_id, delta)
    };

    // Get previous receipt hash for chaining
    let prev_hash = {
        let store = storage.lock().map_err(|e| {
            manifest_core::ManifestError::Config(format!("storage lock poisoned: {e}"))
        })?;
        store.latest_receipt_hash()?
    };

    let action = Action {
        tool: captured.tool_name.clone(),
        input: captured.input.clone(),
        output: captured.output.clone(),
        error: captured.error.clone(),
    };

    // Build and sign the receipt
    let receipt = {
        let mut tree = merkle.lock().map_err(|e| {
            manifest_core::ManifestError::Config(format!("merkle lock poisoned: {e}"))
        })?;

        ReceiptBuilder::new()
            .agent(identity)
            .policy(policy_snapshot)
            .action(action)
            .delta(delta)
            .previous_receipt(prev_hash)
            .build(signer, &mut tree)?
    };

    // Persist the receipt and merkle leaf
    {
        let store = storage.lock().map_err(|e| {
            manifest_core::ManifestError::Config(format!("storage lock poisoned: {e}"))
        })?;

        store.insert_receipt(&receipt, Some(&session_id))?;

        // Persist the merkle leaf
        let hash_hex = receipt.content_hash();
        let hash_bytes: [u8; 32] = hex::decode(
            hash_hex.strip_prefix("sha256:").unwrap_or(&hash_hex),
        )
        .map_err(|e| manifest_core::ManifestError::Signing(format!("bad hex: {e}")))?
        .try_into()
        .map_err(|_| manifest_core::ManifestError::Signing("not 32 bytes".into()))?;

        let leaf_index = merkle
            .lock()
            .map_err(|e| manifest_core::ManifestError::Config(format!("lock: {e}")))?
            .len() as u64
            - 1;

        store.insert_merkle_leaf(leaf_index, &hash_bytes)?;
    }

    tracing::info!(
        tool = %captured.tool_name,
        receipt_id = %receipt.id,
        "receipt generated"
    );

    Ok(())
}
