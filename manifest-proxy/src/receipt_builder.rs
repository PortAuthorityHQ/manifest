use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use manifest_core::{
    Action, ActionError, MerkleTree, ReceiptBuilder, Signer, Storage,
};
use tokio::sync::mpsc;

use crate::session::McpSession;

/// Pre-extracted session state carried with each captured tool call.
///
/// For stdio, this is extracted from the single session. For HTTP,
/// this is extracted from the per-session map at interception time.
pub struct SessionInfo {
    pub identity: manifest_core::AgentIdentity,
    pub policy_snapshot: Option<manifest_core::PolicySnapshot>,
    pub session_id: String,
    pub delta: Option<manifest_core::receipt::Delta>,
}

/// Extract session info from an `McpSession` for a given tool call.
pub fn extract_session_info(
    session: &McpSession,
    tool_name: &str,
    input: &serde_json::Value,
    output: Option<&serde_json::Value>,
) -> SessionInfo {
    let identity = session.identity();
    let policy_snapshot = session.policy_snapshot();
    let session_id = session.session_id.clone();
    let (authorized, violations) = session.check_tool(tool_name, input, output);
    let delta = if policy_snapshot.is_some() {
        Some(manifest_core::receipt::Delta {
            authorized,
            violations,
        })
    } else {
        None
    };
    SessionInfo {
        identity,
        policy_snapshot,
        session_id,
        delta,
    }
}

/// A captured tool call ready for receipt generation.
pub struct CapturedToolCall {
    pub tool_name: String,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub error: Option<ActionError>,
    pub timestamp: DateTime<Utc>,
    /// Pre-extracted session info. If `None`, the receipt worker extracts
    /// it from the shared session (stdio mode).
    pub session_info: Option<SessionInfo>,
}

/// Background worker that consumes captured tool calls and generates signed receipts.
///
/// Runs as a `tokio::spawn`-ed task. Reads from the mpsc channel and for each
/// captured call: extracts session state on the async side, then offloads
/// signing + SQLite writes to a blocking thread via `spawn_blocking` to
/// avoid blocking the tokio runtime.
///
/// The `session` parameter is used for stdio mode where there's a single
/// shared session. For HTTP mode, session info is pre-extracted and carried
/// in `CapturedToolCall.session_info`.
pub async fn receipt_worker(
    mut rx: mpsc::UnboundedReceiver<CapturedToolCall>,
    session: Arc<Mutex<McpSession>>,
    signer: Arc<Signer>,
    merkle: Arc<Mutex<MerkleTree>>,
    storage: Arc<Mutex<Storage>>,
) {
    while let Some(mut captured) = rx.recv().await {
        // Use pre-extracted session info if available (HTTP mode),
        // otherwise extract from the shared session (stdio mode).
        let pre_extracted = captured.session_info.take();
        let session_state = if let Some(info) = pre_extracted {
            (info.identity, info.policy_snapshot, info.session_id, info.delta)
        } else {
            let sess = match session.lock() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("session lock poisoned: {e}");
                    continue;
                }
            };
            let info = extract_session_info(
                &sess,
                &captured.tool_name,
                &captured.input,
                captured.output.as_ref(),
            );
            (info.identity, info.policy_snapshot, info.session_id, info.delta)
        };

        // Offload signing + hashing + SQLite writes to a blocking thread
        let signer = signer.clone();
        let merkle = merkle.clone();
        let storage = storage.clone();
        let tool_name = captured.tool_name.clone();

        let result = tokio::task::spawn_blocking(move || {
            process_captured_call(captured, session_state, &signer, &merkle, &storage)
        })
        .await;

        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(tool = %tool_name, error = %e, "failed to generate receipt");
            }
            Err(e) => {
                tracing::error!(tool = %tool_name, error = %e, "receipt task panicked");
            }
        }
    }

    tracing::debug!("receipt worker shutting down");
}

type SessionState = (
    manifest_core::AgentIdentity,
    Option<manifest_core::PolicySnapshot>,
    String, // session_id
    Option<manifest_core::receipt::Delta>,
);

/// Process a captured tool call on a blocking thread.
///
/// This runs inside `spawn_blocking` so it's safe to do CPU-intensive
/// signing and blocking SQLite IO here without stalling tokio.
fn process_captured_call(
    captured: CapturedToolCall,
    (identity, policy_snapshot, session_id, delta): SessionState,
    signer: &Signer,
    merkle: &Arc<Mutex<MerkleTree>>,
    storage: &Arc<Mutex<Storage>>,
) -> Result<(), manifest_core::ManifestError> {
    // Get previous receipt hash for chaining
    let prev_hash = {
        let store = storage.lock().map_err(|e| {
            manifest_core::ManifestError::Config(format!("storage lock poisoned: {e}"))
        })?;
        store.latest_receipt_hash()?
    };

    // Truncate oversized outputs to prevent receipt bloat.
    // If the serialized output exceeds the threshold, replace it with a
    // hash reference so the receipt stays small but verifiable.
    let output = truncate_if_oversized(captured.output);
    let input = truncate_if_oversized(Some(captured.input)).unwrap_or_default();

    let action = Action {
        tool: captured.tool_name.clone(),
        input,
        output,
        error: captured.error,
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

/// Maximum serialized size (in bytes) for input/output before truncation.
///
/// Payloads larger than this are replaced with a hash reference.
/// Default: 256 KB. Can be overridden via `MANIFEST_MAX_PAYLOAD_BYTES`.
fn max_payload_bytes() -> usize {
    std::env::var("MANIFEST_MAX_PAYLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256 * 1024)
}

/// Replace an oversized JSON value with a compact hash reference.
///
/// If the serialized form exceeds `max_payload_bytes()`, returns:
/// ```json
/// {
///   "_truncated": true,
///   "_original_hash": "sha256:abcdef...",
///   "_original_bytes": 524288
/// }
/// ```
fn truncate_if_oversized(value: Option<serde_json::Value>) -> Option<serde_json::Value> {
    let value = value?;
    let serialized = serde_json::to_vec(&value).unwrap_or_default();
    let max = max_payload_bytes();

    if serialized.len() <= max {
        return Some(value);
    }

    let hash = manifest_core::sha256_hex(&serialized);
    tracing::warn!(
        bytes = serialized.len(),
        max_bytes = max,
        hash = %hash,
        "payload truncated — exceeds size limit"
    );

    Some(serde_json::json!({
        "_truncated": true,
        "_original_hash": hash,
        "_original_bytes": serialized.len(),
    }))
}
