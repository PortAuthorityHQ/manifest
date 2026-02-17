//! HTTP reverse proxy for Streamable HTTP MCP transport.
//!
//! Implements the MCP Streamable HTTP transport (protocol 2025-03-26+):
//! - Client sends JSON-RPC requests via POST to a single endpoint
//! - Server responds with either `application/json` or `text/event-stream`
//! - Manifest intercepts requests and responses for receipt generation
//! - GET requests are proxied for server-initiated SSE streams
//!
//! The JSON-RPC interception logic is identical to the stdio relay — only
//! the framing layer (HTTP + SSE vs newline-delimited JSON) differs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::jsonrpc::JsonRpcMessage;
use crate::mcp;
use crate::pending::PendingCallMap;
use crate::receipt_builder::{extract_session_info, CapturedToolCall};
use crate::session::McpSession;
use manifest_core::{AgentIdentity, PolicyConfig};

/// Per-session state, keyed by `Mcp-Session-Id` from the upstream server.
struct PerSessionState {
    session: McpSession,
    pending: PendingCallMap,
}

/// Shared state for the HTTP proxy handlers.
#[derive(Clone)]
pub struct HttpProxyState {
    /// Upstream MCP server URL (e.g., "http://localhost:9090/mcp").
    pub upstream_url: String,
    /// HTTP client for forwarding requests.
    pub client: reqwest::Client,
    /// Per-session state map, keyed by `Mcp-Session-Id`.
    sessions: Arc<Mutex<HashMap<String, PerSessionState>>>,
    /// Identity config (shared across all sessions).
    identity_config: Option<AgentIdentity>,
    /// Policy config (shared across all sessions).
    policy_config: Option<PolicyConfig>,
    /// Channel to send captured tool calls to the receipt worker.
    pub receipt_tx: mpsc::UnboundedSender<CapturedToolCall>,
    /// Optional bearer token for authentication. If set, all requests must
    /// include `Authorization: Bearer <token>` or receive 401.
    pub auth_token: Option<String>,
}

impl HttpProxyState {
    /// Create a new HTTP proxy state.
    pub fn new(
        upstream_url: String,
        identity_config: Option<AgentIdentity>,
        policy_config: Option<PolicyConfig>,
        receipt_tx: mpsc::UnboundedSender<CapturedToolCall>,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            upstream_url,
            client: reqwest::Client::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            identity_config,
            policy_config,
            receipt_tx,
            auth_token,
        }
    }

    /// Get or create per-session state for the given session ID.
    /// An empty string key is used as the "default" session for servers
    /// that don't send `Mcp-Session-Id` headers.
    fn get_or_create_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(session_id) {
            sessions.insert(
                session_id.to_string(),
                PerSessionState {
                    session: McpSession::new(
                        self.identity_config.clone(),
                        self.policy_config.clone(),
                    ),
                    pending: PendingCallMap::new(),
                },
            );
            tracing::debug!(session_id = %session_id, "created new per-session state");
        }
    }
}

/// Build the Axum router for the HTTP proxy.
///
/// All MCP traffic goes through a single endpoint (e.g., `/mcp`).
/// The proxy forwards requests to the upstream server, intercepting
/// JSON-RPC messages for receipt generation along the way.
pub fn build_router(state: HttpProxyState) -> Router {
    let router = Router::new()
        .route(
            "/mcp",
            axum::routing::post(handle_post)
                .get(handle_get)
                .delete(handle_delete),
        );

    // Add auth middleware if a token is configured
    if state.auth_token.is_some() {
        router
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state)
    } else {
        router.with_state(state)
    }
}

/// Middleware that validates the Bearer token on every request.
async fn auth_middleware(
    State(state): State<HttpProxyState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let expected = match &state.auth_token {
        Some(t) => t,
        None => return next.run(request).await,
    };

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if token == expected => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response(),
    }
}

/// Extract the `Mcp-Session-Id` from headers, defaulting to empty string.
fn extract_session_id(headers: &HeaderMap) -> String {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Handle POST requests — client sending JSON-RPC messages.
///
/// Intercepts the request body, forwards to upstream, then intercepts
/// the response. Supports both JSON and SSE response modes.
async fn handle_post(
    State(state): State<HttpProxyState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Parse the JSON-RPC request body
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid UTF-8").into_response(),
    };

    // Determine the session ID from the request header (empty for initialize)
    let req_session_id = extract_session_id(&headers);
    state.get_or_create_session(&req_session_id);

    // Intercept the request (same logic as stdio relay)
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body_str) {
        intercept_request(&value, &state, &req_session_id);
    }

    // Build the upstream request
    let mut upstream_req = state.client.post(&state.upstream_url).body(body.to_vec());

    // Forward relevant headers
    for key in &[
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
    ] {
        if let Some(val) = headers.get(*key) {
            upstream_req = upstream_req.header(*key, val.as_bytes());
        }
    }

    // Ensure Accept includes both JSON and SSE
    if headers.get("accept").is_none() {
        upstream_req =
            upstream_req.header("accept", "application/json, text/event-stream");
    }

    // Send to upstream
    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to reach upstream MCP server");
            return (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Check if the upstream assigned a new session ID (happens on initialize response)
    let upstream_session_id = resp_headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // If the upstream assigned a session ID and the request had no session ID,
    // migrate the default session state to the new key.
    if !upstream_session_id.is_empty() && req_session_id.is_empty() {
        let mut sessions = state.sessions.lock().unwrap();
        if let Some(session_state) = sessions.remove("") {
            sessions.insert(upstream_session_id.clone(), session_state);
            tracing::debug!(
                session_id = %upstream_session_id,
                "migrated default session to upstream session ID"
            );
        }
    }

    // Use the upstream session ID for response interception if available
    let resp_session_id = if !upstream_session_id.is_empty() {
        &upstream_session_id
    } else {
        &req_session_id
    };

    // Build response headers to forward back to the client
    let mut response_headers = HeaderMap::new();
    for key in &["content-type", "mcp-session-id", "mcp-protocol-version"] {
        if let Some(val) = resp_headers.get(*key) {
            if let Ok(name) = axum::http::header::HeaderName::from_bytes(key.as_bytes()) {
                response_headers.insert(name, val.clone());
            }
        }
    }

    if content_type.contains("text/event-stream") {
        // SSE response — stream events through, intercepting each one
        let byte_stream = upstream_resp.bytes_stream();
        let state_clone = state.clone();
        let sse_session_id = resp_session_id.to_string();

        let sse_stream = byte_stream.map(move |chunk| {
            match chunk {
                Ok(bytes) => {
                    // Parse SSE events and intercept JSON-RPC messages
                    let text = String::from_utf8_lossy(&bytes);
                    intercept_sse_chunk(&text, &state_clone, &sse_session_id);
                    Ok::<_, std::io::Error>(bytes)
                }
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        });

        let body = Body::from_stream(sse_stream);

        (status, response_headers, body).into_response()
    } else {
        // JSON response — intercept the full body
        let resp_body = match upstream_resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "failed to read upstream response");
                return (StatusCode::BAD_GATEWAY, "upstream read error").into_response();
            }
        };

        if let Ok(text) = std::str::from_utf8(&resp_body) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                intercept_response(&value, &state, resp_session_id);
            }
        }

        (status, response_headers, resp_body).into_response()
    }
}

/// Handle GET requests — client opening an SSE stream for server-initiated messages.
async fn handle_get(
    State(state): State<HttpProxyState>,
    headers: HeaderMap,
) -> Response {
    let session_id = extract_session_id(&headers);
    let mut upstream_req = state.client.get(&state.upstream_url);

    for key in &["accept", "mcp-session-id", "mcp-protocol-version", "last-event-id"] {
        if let Some(val) = headers.get(*key) {
            upstream_req = upstream_req.header(*key, val.as_bytes());
        }
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to reach upstream for GET SSE");
            return (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    let mut response_headers = HeaderMap::new();
    if let Some(ct) = resp_headers.get("content-type") {
        response_headers.insert("content-type", ct.clone());
    }
    if let Some(sid) = resp_headers.get("mcp-session-id") {
        response_headers.insert(
            axum::http::header::HeaderName::from_static("mcp-session-id"),
            sid.clone(),
        );
    }

    let state_clone = state.clone();
    let byte_stream = upstream_resp.bytes_stream().map(move |chunk| {
        match chunk {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                intercept_sse_chunk(&text, &state_clone, &session_id);
                Ok::<_, std::io::Error>(bytes)
            }
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    });

    let body = Body::from_stream(byte_stream);
    (status, response_headers, body).into_response()
}

/// Handle DELETE requests — client terminating the session.
async fn handle_delete(
    State(state): State<HttpProxyState>,
    headers: HeaderMap,
) -> Response {
    let mut upstream_req = state.client.delete(&state.upstream_url);

    if let Some(sid) = headers.get("mcp-session-id") {
        upstream_req = upstream_req.header("mcp-session-id", sid.as_bytes());
    }

    match upstream_req.send().await {
        Ok(resp) => {
            let status = resp.status();
            tracing::info!(%status, "session terminated via DELETE");
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to forward DELETE to upstream");
            (StatusCode::BAD_GATEWAY, "upstream error").into_response()
        }
    }
}

/// Intercept an incoming JSON-RPC request (from the client POST body).
fn intercept_request(value: &serde_json::Value, state: &HttpProxyState, session_id: &str) {
    match JsonRpcMessage::parse(value.clone()) {
        Ok(JsonRpcMessage::Request(ref req)) if mcp::is_initialize(&req.method) => {
            if let Some(ref params) = req.params {
                if let Ok(mut sessions) = state.sessions.lock() {
                    if let Some(s) = sessions.get_mut(session_id) {
                        s.session.on_initialize_request(params);
                    }
                }
            }
            tracing::debug!("intercepted initialize request (HTTP)");
        }
        Ok(JsonRpcMessage::Request(ref req)) if mcp::is_tool_call(&req.method) => {
            if let Some(ref params) = req.params {
                if let Some((tool_name, input)) = mcp::extract_tool_call(params) {
                    if let Ok(mut sessions) = state.sessions.lock() {
                        if let Some(s) = sessions.get_mut(session_id) {
                            s.pending.insert(&req.id, tool_name.clone(), input);
                        }
                    }
                    tracing::debug!(tool = %tool_name, "intercepted tools/call request (HTTP)");
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("failed to parse JSON-RPC request (HTTP): {e}");
        }
    }
}

/// Intercept a JSON-RPC response (from the upstream server).
fn intercept_response(value: &serde_json::Value, state: &HttpProxyState, session_id: &str) {
    match JsonRpcMessage::parse(value.clone()) {
        Ok(JsonRpcMessage::Response(ref resp)) => {
            // Check for initialize response
            if let Some(ref result) = resp.result {
                if result.get("serverInfo").is_some() {
                    if let Ok(mut sessions) = state.sessions.lock() {
                        if let Some(s) = sessions.get_mut(session_id) {
                            if !s.session.initialized {
                                s.session.on_initialize_response(result);
                                tracing::debug!("captured server capabilities (HTTP)");
                            }
                        }
                    }
                }
            }

            // Match against pending tool calls
            let pending_call = {
                if let Ok(mut sessions) = state.sessions.lock() {
                    sessions
                        .get_mut(session_id)
                        .and_then(|s| s.pending.remove(&resp.id))
                } else {
                    None
                }
            };

            if let Some(call) = pending_call {
                // Extract session info now, while we have access to the session map
                let session_info = {
                    state
                        .sessions
                        .lock()
                        .ok()
                        .and_then(|sessions| {
                            sessions.get(session_id).map(|s| {
                                extract_session_info(
                                    &s.session,
                                    &call.tool_name,
                                    &call.input,
                                    resp.result.as_ref(),
                                )
                            })
                        })
                };

                let captured = CapturedToolCall {
                    tool_name: call.tool_name.clone(),
                    input: call.input,
                    output: resp.result.clone(),
                    error: resp.error.as_ref().map(|e| manifest_core::ActionError {
                        code: e.code,
                        message: e.message.clone(),
                        data: e.data.clone(),
                    }),
                    timestamp: call.timestamp,
                    session_info,
                };

                if let Err(e) = state.receipt_tx.send(captured) {
                    tracing::warn!(tool = %call.tool_name, "failed to send to receipt worker (HTTP): {e}");
                } else {
                    tracing::debug!(tool = %call.tool_name, "captured tools/call response (HTTP)");
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("failed to parse JSON-RPC response (HTTP): {e}");
        }
    }
}

/// Parse SSE event chunks and intercept any JSON-RPC messages within.
///
/// SSE events have the format:
/// ```text
/// event: message
/// data: {"jsonrpc":"2.0", ...}
///
/// ```
fn intercept_sse_chunk(text: &str, state: &HttpProxyState, session_id: &str) {
    for line in text.lines() {
        let data = if let Some(stripped) = line.strip_prefix("data: ") {
            stripped
        } else if let Some(stripped) = line.strip_prefix("data:") {
            stripped
        } else {
            continue;
        };

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
            intercept_response(&value, state, session_id);
        }
    }
}
