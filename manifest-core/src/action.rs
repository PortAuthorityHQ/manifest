use serde::{Deserialize, Serialize};

/// A captured tool call action: what the agent sent and what came back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// The tool name (e.g. "db_query", "send_email").
    pub tool: String,

    /// The input parameters sent to the tool.
    pub input: serde_json::Value,

    /// The tool's output (None if the call errored).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,

    /// Error details if the tool call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ActionError>,
}

/// Error details from a failed tool call, matching JSON-RPC error structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_success_serialization() {
        let action = Action {
            tool: "db_query".to_string(),
            input: serde_json::json!({"query": "SELECT 1"}),
            output: Some(serde_json::json!({"rows": 1})),
            error: None,
        };
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(json["tool"], "db_query");
        assert!(json.get("error").is_none()); // None fields omitted
    }

    #[test]
    fn action_error_serialization() {
        let action = Action {
            tool: "db_query".to_string(),
            input: serde_json::json!({"query": "DROP TABLE users"}),
            output: None,
            error: Some(ActionError {
                code: -32603,
                message: "permission denied".to_string(),
                data: None,
            }),
        };
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(json["error"]["code"], -32603);
        assert!(json.get("output").is_none());
    }
}
