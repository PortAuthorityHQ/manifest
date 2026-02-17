use serde::{Deserialize, Serialize};
use serde_json::Value;

use manifest_core::ManifestError;

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC 2.0 notification (no `id` field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A classified JSON-RPC message.
#[derive(Debug, Clone)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

impl JsonRpcMessage {
    /// Parse a raw JSON value into a typed JSON-RPC message.
    ///
    /// Classification logic:
    /// - Has `method` + `id` -> Request
    /// - Has `method` but no `id` -> Notification
    /// - Has `id` but no `method` -> Response
    /// - Otherwise -> Protocol error
    pub fn parse(value: Value) -> Result<Self, ManifestError> {
        let obj = value
            .as_object()
            .ok_or_else(|| ManifestError::Protocol("JSON-RPC message must be an object".into()))?;

        let has_method = obj.contains_key("method");
        let has_id = obj.contains_key("id");

        if has_method && has_id {
            let req: JsonRpcRequest = serde_json::from_value(Value::Object(obj.clone()))?;
            Ok(JsonRpcMessage::Request(req))
        } else if has_method {
            let notif: JsonRpcNotification =
                serde_json::from_value(Value::Object(obj.clone()))?;
            Ok(JsonRpcMessage::Notification(notif))
        } else if has_id {
            let resp: JsonRpcResponse = serde_json::from_value(Value::Object(obj.clone()))?;
            Ok(JsonRpcMessage::Response(resp))
        } else {
            Err(ManifestError::Protocol(
                "message has neither 'method' nor 'id'".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request() {
        let val = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "db_query"}
        });
        match JsonRpcMessage::parse(val).unwrap() {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "tools/call");
                assert_eq!(req.id, serde_json::json!(1));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parse_response_success() {
        let val = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"rows": 42}
        });
        match JsonRpcMessage::parse(val).unwrap() {
            JsonRpcMessage::Response(resp) => {
                assert_eq!(resp.id, serde_json::json!(1));
                assert!(resp.result.is_some());
                assert!(resp.error.is_none());
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn parse_response_error() {
        let val = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32603, "message": "internal error"}
        });
        match JsonRpcMessage::parse(val).unwrap() {
            JsonRpcMessage::Response(resp) => {
                let err = resp.error.unwrap();
                assert_eq!(err.code, -32603);
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn parse_notification() {
        let val = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        match JsonRpcMessage::parse(val).unwrap() {
            JsonRpcMessage::Notification(notif) => {
                assert_eq!(notif.method, "notifications/initialized");
            }
            _ => panic!("expected notification"),
        }
    }

    #[test]
    fn parse_string_id() {
        let val = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "abc-123",
            "method": "tools/call"
        });
        match JsonRpcMessage::parse(val).unwrap() {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.id, serde_json::json!("abc-123"));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parse_invalid_message() {
        let val = serde_json::json!({"jsonrpc": "2.0"});
        assert!(JsonRpcMessage::parse(val).is_err());
    }

    #[test]
    fn parse_non_object() {
        let val = serde_json::json!("not an object");
        assert!(JsonRpcMessage::parse(val).is_err());
    }
}
