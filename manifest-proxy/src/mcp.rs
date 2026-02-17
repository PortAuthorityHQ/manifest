use serde_json::Value;

/// Extract the tool name and input arguments from a `tools/call` request params.
///
/// MCP `tools/call` format:
/// ```json
/// { "name": "db_query", "arguments": { "query": "SELECT 1" } }
/// ```
pub fn extract_tool_call(params: &Value) -> Option<(String, Value)> {
    let name = params.get("name")?.as_str()?.to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));
    Some((name, arguments))
}

/// Extract `clientInfo` from an `initialize` request params.
///
/// Returns `(name, version)` if present.
pub fn extract_client_info(params: &Value) -> Option<(String, Option<String>)> {
    let client_info = params.get("clientInfo")?;
    let name = client_info.get("name")?.as_str()?.to_string();
    let version = client_info
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);
    Some((name, version))
}

/// Extract `serverInfo` and `capabilities` from an `initialize` response result.
///
/// Returns `(server_info, capabilities)` as raw JSON values.
pub fn extract_server_info(result: &Value) -> Option<(Value, Option<Value>)> {
    let server_info = result.get("serverInfo")?.clone();
    let capabilities = result.get("capabilities").cloned();
    Some((server_info, capabilities))
}

/// Check if a method is a `tools/call`.
pub fn is_tool_call(method: &str) -> bool {
    method == "tools/call"
}

/// Check if a method is `initialize`.
pub fn is_initialize(method: &str) -> bool {
    method == "initialize"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tool_call_full() {
        let params = serde_json::json!({
            "name": "db_query",
            "arguments": {"query": "SELECT * FROM orders"}
        });
        let (name, args) = extract_tool_call(&params).unwrap();
        assert_eq!(name, "db_query");
        assert_eq!(args["query"], "SELECT * FROM orders");
    }

    #[test]
    fn extract_tool_call_no_arguments() {
        let params = serde_json::json!({"name": "list_tables"});
        let (name, args) = extract_tool_call(&params).unwrap();
        assert_eq!(name, "list_tables");
        assert!(args.is_object());
    }

    #[test]
    fn extract_tool_call_missing_name() {
        let params = serde_json::json!({"arguments": {}});
        assert!(extract_tool_call(&params).is_none());
    }

    #[test]
    fn extract_client_info_full() {
        let params = serde_json::json!({
            "clientInfo": {
                "name": "claude-desktop",
                "version": "1.2.0"
            },
            "protocolVersion": "2024-11-05"
        });
        let (name, version) = extract_client_info(&params).unwrap();
        assert_eq!(name, "claude-desktop");
        assert_eq!(version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn extract_client_info_no_version() {
        let params = serde_json::json!({
            "clientInfo": {"name": "custom-agent"}
        });
        let (name, version) = extract_client_info(&params).unwrap();
        assert_eq!(name, "custom-agent");
        assert!(version.is_none());
    }

    #[test]
    fn extract_server_info_full() {
        let result = serde_json::json!({
            "serverInfo": {
                "name": "postgres-mcp",
                "version": "0.3.0"
            },
            "capabilities": {
                "tools": {"listChanged": true},
                "logging": {}
            }
        });
        let (info, caps) = extract_server_info(&result).unwrap();
        assert_eq!(info["name"], "postgres-mcp");
        assert!(caps.is_some());
        assert!(caps.unwrap()["logging"].is_object());
    }

    #[test]
    fn extract_server_info_no_capabilities() {
        let result = serde_json::json!({
            "serverInfo": {"name": "minimal-server"}
        });
        let (info, caps) = extract_server_info(&result).unwrap();
        assert_eq!(info["name"], "minimal-server");
        assert!(caps.is_none());
    }

    #[test]
    fn method_checks() {
        assert!(is_tool_call("tools/call"));
        assert!(!is_tool_call("tools/list"));
        assert!(is_initialize("initialize"));
        assert!(!is_initialize("initialized"));
    }
}
