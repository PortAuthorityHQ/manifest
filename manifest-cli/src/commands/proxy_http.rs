use std::sync::{Arc, Mutex};
use std::time::Duration;

use manifest_core::{
    AgentIdentity, ManifestError, MerkleTree, PolicyConfig, Signer, Storage, StorageBackend,
};
use manifest_proxy::http_relay::{build_router, spawn_session_reaper, HttpProxyState};
use manifest_proxy::receipt_builder::{receipt_worker, AlertConfig};
use manifest_proxy::session::McpSession;
use tokio::sync::mpsc;

use crate::commands::init::{resolve_db_path, resolve_key_path};

/// Start the HTTP reverse proxy for remote MCP servers.
pub async fn run(
    upstream_url: &str,
    port: u16,
    identity_path: Option<&str>,
    policy_path: Option<&str>,
    key_path: Option<&str>,
    db_path: Option<&str>,
    auth_token: Option<&str>,
    rate_limit: Option<u64>,
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

    // Restore Merkle tree
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

    // Create a dummy session for the receipt worker (HTTP mode uses per-session
    // state via session_info on CapturedToolCall, so this is only a fallback).
    let dummy_session = Arc::new(Mutex::new(McpSession::new(identity.clone(), policy.clone())));
    let (receipt_tx, receipt_rx) = mpsc::unbounded_channel();

    // Start background receipt worker
    let alerts = AlertConfig::new(webhook_url.map(|s| s.to_string()));
    let worker_handle = tokio::spawn({
        let signer = signer.clone();
        let merkle = merkle.clone();
        let storage = storage.clone();
        async move {
            receipt_worker(receipt_rx, dummy_session, signer, merkle, storage, alerts).await;
        }
    });

    // Build the HTTP proxy with per-session state map
    let state = HttpProxyState::new(
        upstream_url.to_string(),
        identity,
        policy,
        receipt_tx,
        auth_token.map(|s| s.to_string()),
        rate_limit,
    );

    // Start background session reaper (evicts idle sessions)
    let reaper_handle = spawn_session_reaper(state.clone());

    let app = build_router(state);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    eprintln!("Manifest HTTP proxy listening on http://{addr}");
    eprintln!("Upstream MCP server: {upstream_url}");
    if auth_token.is_some() {
        eprintln!("Authentication: Bearer token required");
    }
    if let Some(rps) = rate_limit {
        eprintln!("Rate limit: {rps} requests/second");
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ManifestError::Config(format!("failed to bind {addr}: {e}")))?;

    // Run the server — blocks until shutdown signal
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| ManifestError::Config(format!("server error: {e}")))?;

    // Stop the session reaper
    reaper_handle.abort();

    // Wait for receipt worker to drain
    tracing::debug!("waiting for receipt worker to drain");
    match tokio::time::timeout(Duration::from_secs(10), worker_handle).await {
        Ok(Ok(())) => tracing::debug!("receipt worker drained"),
        Ok(Err(e)) => tracing::warn!(error = %e, "receipt worker panicked"),
        Err(_) => tracing::warn!("receipt worker drain timeout"),
    }

    Ok(())
}

/// Wait for Ctrl+C to initiate graceful shutdown.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("shutdown signal received");
}
