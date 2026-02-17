use std::sync::{Arc, Mutex};

use manifest_core::ManifestError;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::jsonrpc::JsonRpcMessage;
use crate::mcp;
use crate::pending::PendingCallMap;
use crate::receipt_builder::CapturedToolCall;
use crate::session::McpSession;

/// Run the bidirectional stdio relay between agent and child MCP server.
///
/// This is the core of the proxy. It:
/// - Reads newline-delimited JSON from the agent's stdin, forwards to child stdin
/// - Reads newline-delimited JSON from the child's stdout, forwards to agent stdout
/// - Intercepts `initialize` and `tools/call` messages for receipt generation
/// - Forwards raw bytes (not re-serialized JSON) to preserve exact messages
/// - Sends captured tool calls to the receipt worker via an mpsc channel
///
/// Lifecycle:
/// - When agent stdin reaches EOF, child stdin is closed (signaling the child to finish)
/// - The relay then continues reading child stdout until the child also closes
/// - When child stdout reaches EOF, the relay exits
pub async fn run_relay(
    agent_reader: BufReader<tokio::io::Stdin>,
    mut agent_writer: tokio::io::Stdout,
    child_stdin: tokio::process::ChildStdin,
    child_stdout: BufReader<tokio::process::ChildStdout>,
    session: Arc<Mutex<McpSession>>,
    receipt_tx: mpsc::UnboundedSender<CapturedToolCall>,
) -> Result<(), ManifestError> {
    let pending = Arc::new(Mutex::new(PendingCallMap::new()));

    // Wrap child_stdin in an Option so we can drop it when agent EOF is reached
    let child_stdin = Arc::new(tokio::sync::Mutex::new(Some(child_stdin)));

    // Spawn agent->child as a separate task so it runs concurrently
    let a2c_pending = pending.clone();
    let a2c_session = session.clone();
    let a2c_child_stdin = child_stdin.clone();
    let agent_to_child_handle = tokio::spawn(async move {
        let result = relay_agent_to_child(
            agent_reader,
            a2c_child_stdin.clone(),
            a2c_session,
            a2c_pending,
        )
        .await;

        // Agent stdin EOF reached — close child stdin to signal the child
        tracing::debug!("agent stdin EOF, closing child stdin");
        let _ = a2c_child_stdin.lock().await.take();

        result
    });

    // Run child->agent on the current task (this is the "main" direction)
    let result = relay_child_to_agent(
        child_stdout,
        &mut agent_writer,
        session,
        pending,
        receipt_tx,
    )
    .await;

    tracing::debug!("child stdout EOF, relay complete");

    // Wait for the agent->child task to finish (it may already be done)
    let _ = agent_to_child_handle.await;

    result
}

/// Relay: agent stdin -> parse & intercept -> child stdin.
async fn relay_agent_to_child(
    reader: BufReader<tokio::io::Stdin>,
    child_stdin: Arc<tokio::sync::Mutex<Option<tokio::process::ChildStdin>>>,
    session: Arc<Mutex<McpSession>>,
    pending: Arc<Mutex<PendingCallMap>>,
) -> Result<(), ManifestError> {
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        // Try to parse and intercept, but always forward the raw line
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            match JsonRpcMessage::parse(value) {
                Ok(JsonRpcMessage::Request(ref req)) if mcp::is_initialize(&req.method) => {
                    if let Some(ref params) = req.params {
                        if let Ok(mut sess) = session.lock() {
                            sess.on_initialize_request(params);
                        }
                    }
                    tracing::debug!("intercepted initialize request");
                }
                Ok(JsonRpcMessage::Request(ref req)) if mcp::is_tool_call(&req.method) => {
                    if let Some(ref params) = req.params {
                        if let Some((tool_name, input)) = mcp::extract_tool_call(params) {
                            if let Ok(mut p) = pending.lock() {
                                p.insert(&req.id, tool_name.clone(), input);
                            }
                            tracing::debug!(tool = %tool_name, "intercepted tools/call request");
                        }
                    }
                }
                Ok(_) => {} // Other messages pass through silently
                Err(e) => {
                    tracing::warn!("failed to parse JSON-RPC message: {e}");
                }
            }
        }

        // Forward the raw line to child stdin (if still open)
        let mut guard = child_stdin.lock().await;
        if let Some(ref mut stdin) = *guard {
            stdin.write_all(line.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
        }
    }

    Ok(())
}

/// Relay: child stdout -> parse & intercept -> agent stdout.
async fn relay_child_to_agent(
    reader: BufReader<tokio::process::ChildStdout>,
    agent_writer: &mut tokio::io::Stdout,
    session: Arc<Mutex<McpSession>>,
    pending: Arc<Mutex<PendingCallMap>>,
    receipt_tx: mpsc::UnboundedSender<CapturedToolCall>,
) -> Result<(), ManifestError> {
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        // Forward the raw line FIRST — before any receipt processing.
        // This ensures the agent sees the response with minimal latency.
        agent_writer.write_all(line.as_bytes()).await?;
        agent_writer.write_all(b"\n").await?;
        agent_writer.flush().await?;

        // Now parse and intercept (non-blocking for the agent)
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            match JsonRpcMessage::parse(value) {
                Ok(JsonRpcMessage::Response(ref resp)) => {
                    // Check if this is the initialize response
                    if let Some(ref result) = resp.result {
                        if result.get("serverInfo").is_some() {
                            if let Ok(mut sess) = session.lock() {
                                if !sess.initialized {
                                    sess.on_initialize_response(result);
                                    tracing::debug!("captured server capabilities from initialize response");
                                }
                            }
                        }
                    }

                    // Check if this matches a pending tools/call
                    let pending_call = {
                        if let Ok(mut p) = pending.lock() {
                            p.remove(&resp.id)
                        } else {
                            None
                        }
                    };

                    if let Some(call) = pending_call {
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
                            session_info: None, // stdio uses shared session
                        };

                        if let Err(e) = receipt_tx.send(captured) {
                            tracing::warn!(
                                tool = %call.tool_name,
                                "failed to send captured tool call to receipt worker: {e}"
                            );
                        } else {
                            tracing::debug!(tool = %call.tool_name, "captured tools/call response");
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("failed to parse JSON-RPC response: {e}");
                }
            }
        }
    }

    Ok(())
}
