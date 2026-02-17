use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

/// A pending `tools/call` request awaiting its response.
pub struct PendingCall {
    pub tool_name: String,
    pub input: Value,
    pub timestamp: DateTime<Utc>,
}

/// Tracks in-flight tool calls keyed by their JSON-RPC request ID.
///
/// When a `tools/call` request is intercepted, it's inserted here.
/// When the matching response arrives, it's removed and paired up
/// for receipt generation.
pub struct PendingCallMap {
    calls: HashMap<String, PendingCall>,
}

impl PendingCallMap {
    pub fn new() -> Self {
        Self {
            calls: HashMap::new(),
        }
    }

    /// Register a pending tool call. Returns the string key used.
    pub fn insert(&mut self, request_id: &Value, tool_name: String, input: Value) -> String {
        let key = id_to_key(request_id);
        self.calls.insert(
            key.clone(),
            PendingCall {
                tool_name,
                input,
                timestamp: Utc::now(),
            },
        );
        key
    }

    /// Remove and return the pending call matching a response ID.
    pub fn remove(&mut self, response_id: &Value) -> Option<PendingCall> {
        let key = id_to_key(response_id);
        self.calls.remove(&key)
    }

    /// Number of in-flight calls.
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }
}

impl Default for PendingCallMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a JSON-RPC ID (number or string) to a consistent string key.
fn id_to_key(id: &Value) -> String {
    match id {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_remove_numeric_id() {
        let mut map = PendingCallMap::new();
        let id = serde_json::json!(42);
        map.insert(&id, "db_query".into(), serde_json::json!({}));

        assert_eq!(map.len(), 1);
        let call = map.remove(&id).unwrap();
        assert_eq!(call.tool_name, "db_query");
        assert!(map.is_empty());
    }

    #[test]
    fn insert_and_remove_string_id() {
        let mut map = PendingCallMap::new();
        let id = serde_json::json!("req-abc-123");
        map.insert(&id, "send_email".into(), serde_json::json!({"to": "a@b.com"}));

        let call = map.remove(&id).unwrap();
        assert_eq!(call.tool_name, "send_email");
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut map = PendingCallMap::new();
        assert!(map.remove(&serde_json::json!(999)).is_none());
    }

    #[test]
    fn multiple_pending_calls() {
        let mut map = PendingCallMap::new();
        map.insert(&serde_json::json!(1), "tool_a".into(), serde_json::json!({}));
        map.insert(&serde_json::json!(2), "tool_b".into(), serde_json::json!({}));
        map.insert(&serde_json::json!(3), "tool_c".into(), serde_json::json!({}));

        assert_eq!(map.len(), 3);

        // Remove out of order
        let call = map.remove(&serde_json::json!(2)).unwrap();
        assert_eq!(call.tool_name, "tool_b");
        assert_eq!(map.len(), 2);
    }
}
