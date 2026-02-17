use std::sync::{Arc, Mutex};
use std::time::Duration;

use manifest_core::{
    AgentIdentity, ManifestError, MerkleTree, PolicyConfig, Signer, Storage, StorageBackend,
};
use manifest_proxy::child::ChildProcess;
use manifest_proxy::receipt_builder::{receipt_worker, AlertConfig};
use manifest_proxy::relay::run_relay;
use manifest_proxy::session::McpSession;
use tokio::io::BufReader;
use tokio::sync::mpsc;

use crate::commands::init::{resolve_db_path, resolve_key_path};

/// Start the proxy, wrapping an MCP server.
pub async fn run(
    server_cmd: &str,
    identity_path: Option<&str>,
    policy_path: Option<&str>,
    key_path: Option<&str>,
    db_path: Option<&str>,
    webhook_url: Option<&str>,
) -> Result<(), ManifestError> {
    let key_file = resolve_key_path(key_path);
    let db_file = resolve_db_path(db_path);

    // Load or generate signing key
    let signer = if key_file.exists() {
        tracing::info!(path = %key_file.display(), "loading signing key");
        Signer::from_file(&key_file)?
    } else {
        tracing::info!(path = %key_file.display(), "generating new signing key");
        let signer = Signer::generate();
        signer.save(&key_file)?;
        signer
    };
    let signer = Arc::new(signer);

    // Open storage
    tracing::info!(path = %db_file.display(), "opening receipt database");
    let storage = Storage::open(&db_file)?;

    // Restore Merkle tree from stored leaves
    let leaves = storage.load_merkle_leaves()?;
    let merkle = MerkleTree::from_leaves(leaves);
    tracing::info!(leaves = merkle.len(), "restored Merkle tree");

    let storage = Arc::new(Mutex::new(storage));
    let merkle = Arc::new(Mutex::new(merkle));

    // Load identity config
    let identity = match identity_path {
        Some(path) => {
            let id = AgentIdentity::from_config_file(std::path::Path::new(path))?;
            tracing::info!(agent = %id.name, "loaded identity config");
            Some(id)
        }
        None => None,
    };

    // Load policy config
    let policy = match policy_path {
        Some(path) => {
            let p = PolicyConfig::load(std::path::Path::new(path))?;
            tracing::info!(rules = p.policies.len(), "loaded policy config");
            Some(p)
        }
        None => None,
    };

    // Create session
    let session = Arc::new(Mutex::new(McpSession::new(identity, policy)));

    // Spawn child process
    tracing::info!(command = %server_cmd, "spawning MCP server");
    let (child, child_stdio) = ChildProcess::spawn(server_cmd).await?;

    // Receipt channel — unbounded so it never back-pressures the relay
    let (receipt_tx, receipt_rx) = mpsc::unbounded_channel();

    // Start the background receipt worker
    let worker_session = session.clone();
    let worker_signer = signer.clone();
    let worker_merkle = merkle.clone();
    let worker_storage = storage.clone();
    let alerts = AlertConfig::new(webhook_url.map(|s| s.to_string()));
    let worker_handle = tokio::spawn(async move {
        receipt_worker(receipt_rx, worker_session, worker_signer, worker_merkle, worker_storage, alerts).await;
    });

    // Run the relay (blocks until agent or child disconnects)
    let agent_reader = BufReader::new(tokio::io::stdin());
    let agent_writer = tokio::io::stdout();

    let result = run_relay(
        agent_reader,
        agent_writer,
        child_stdio.stdin,
        child_stdio.stdout,
        session,
        receipt_tx,
    )
    .await;

    // receipt_tx was moved into run_relay and is now dropped, which closes the
    // channel. The receipt worker will drain any remaining items and then exit.
    // We await it with a timeout to guarantee we don't hang forever.
    tracing::debug!("waiting for receipt worker to drain");
    match tokio::time::timeout(Duration::from_secs(10), worker_handle).await {
        Ok(Ok(())) => {
            tracing::debug!("receipt worker drained successfully");
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "receipt worker task panicked");
        }
        Err(_) => {
            tracing::warn!("receipt worker did not drain within 10s, shutting down anyway");
        }
    }

    // Shutdown child gracefully
    tracing::info!("shutting down MCP server");
    if let Err(e) = child.shutdown(Duration::from_secs(5)).await {
        tracing::warn!(error = %e, "error during child shutdown");
    }

    result
}
