//! Mock MCP server for testing the manifest proxy.
//!
//! Reads newline-delimited JSON-RPC from stdin, responds on stdout.
//! Supports:
//!   - `initialize` — returns server info and capabilities
//!   - `tools/list`  — returns a list of available tools
//!   - `tools/call`  — echoes the input back as the result (or simulates errors)
//!   - `notifications/initialized` — acknowledged silently
//!
//! Special tool behaviors:
//!   - `echo`       — returns the input arguments as the result
//!   - `add`        — adds two numbers: {"a": 2, "b": 3} -> {"sum": 5}
//!   - `fail`       — always returns a JSON-RPC error
//!   - `slow`       — waits 500ms before responding (for latency testing)
//!   - `db_query`   — returns mock database rows
//!   - anything else — echoes input back

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::thread;
use std::time::Duration;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Notifications have no `id` — don't respond
        if msg.get("method").is_some() && msg.get("id").is_none() {
            continue;
        }

        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "mock-mcp-server",
                        "version": "0.1.0"
                    },
                    "capabilities": {
                        "tools": { "listChanged": false },
                        "logging": {}
                    }
                }
            }),

            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echoes back the input",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "message": { "type": "string" }
                                }
                            }
                        },
                        {
                            "name": "add",
                            "description": "Adds two numbers",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "a": { "type": "number" },
                                    "b": { "type": "number" }
                                },
                                "required": ["a", "b"]
                            }
                        },
                        {
                            "name": "db_query",
                            "description": "Runs a mock database query",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "query": { "type": "string" }
                                },
                                "required": ["query"]
                            }
                        },
                        {
                            "name": "fail",
                            "description": "Always fails (for testing error receipts)",
                            "inputSchema": { "type": "object" }
                        },
                        {
                            "name": "slow",
                            "description": "Responds after 500ms delay",
                            "inputSchema": { "type": "object" }
                        }
                    ]
                }
            }),

            "tools/call" => {
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                match tool_name {
                    "echo" => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string(&arguments).unwrap_or_default()
                            }]
                        }
                    }),

                    "add" => {
                        let a = arguments.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let b = arguments.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": format!("{}", a + b)
                                }]
                            }
                        })
                    }

                    "db_query" => {
                        let query = arguments.get("query").and_then(|v| v.as_str()).unwrap_or("");
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": format!("{{\"rows\": 42, \"query\": \"{}\"}}", query)
                                }]
                            }
                        })
                    }

                    "fail" => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": "permission denied: simulated failure"
                        }
                    }),

                    "slow" => {
                        thread::sleep(Duration::from_millis(500));
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": "slow response completed"
                                }]
                            }
                        })
                    }

                    _ => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string(&arguments).unwrap_or_default()
                            }]
                        }
                    }),
                }
            }

            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("method not found: {}", method)
                }
            }),
        };

        let response_str = serde_json::to_string(&response).unwrap();
        if writeln!(out, "{}", response_str).is_err() {
            break; // stdout closed (proxy shut down)
        }
        if out.flush().is_err() {
            break;
        }
    }
}
