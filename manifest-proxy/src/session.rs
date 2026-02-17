use manifest_core::{AgentIdentity, PolicyConfig, PolicySnapshot};
use serde_json::Value;
use uuid::Uuid;

use crate::mcp;

/// Tracks MCP session state: identity, policy, server capabilities, and lifecycle.
pub struct McpSession {
    /// Unique ID for this proxy session.
    pub session_id: String,

    /// Identity from config file (highest priority).
    config_identity: Option<AgentIdentity>,

    /// Identity extracted from the MCP `initialize` handshake.
    handshake_identity: Option<AgentIdentity>,

    /// Policy configuration (optional).
    policy: Option<PolicyConfig>,

    /// Server info from the `initialize` response.
    /// Captures what the server claimed it could do — critical for disputes.
    pub server_info: Option<Value>,

    /// Server capabilities from the `initialize` response.
    /// Records whether the server supports logging, sampling, etc.
    pub server_capabilities: Option<Value>,

    /// Whether the initialize handshake has completed.
    pub initialized: bool,
}

impl McpSession {
    pub fn new(
        config_identity: Option<AgentIdentity>,
        policy: Option<PolicyConfig>,
    ) -> Self {
        Self {
            session_id: Uuid::now_v7().to_string(),
            config_identity,
            handshake_identity: None,
            policy,
            server_info: None,
            server_capabilities: None,
            initialized: false,
        }
    }

    /// Called when we intercept an `initialize` request from the agent.
    /// Extracts identity from `clientInfo`.
    pub fn on_initialize_request(&mut self, params: &Value) {
        if let Some((name, version)) = mcp::extract_client_info(params) {
            self.handshake_identity =
                Some(AgentIdentity::from_mcp_client_info(&name, version.as_deref()));
        }
    }

    /// Called when we intercept the `initialize` response from the server.
    /// Captures `serverInfo` and `capabilities`.
    pub fn on_initialize_response(&mut self, result: &Value) {
        if let Some((server_info, capabilities)) = mcp::extract_server_info(result) {
            self.server_info = Some(server_info);
            self.server_capabilities = capabilities;
        }
        self.initialized = true;
    }

    /// Get the current agent identity.
    ///
    /// Priority: config file > MCP handshake > environment fallback.
    pub fn identity(&self) -> AgentIdentity {
        if let Some(ref id) = self.config_identity {
            return id.clone();
        }
        if let Some(ref id) = self.handshake_identity {
            return id.clone();
        }
        AgentIdentity::from_environment()
    }

    /// Get the current policy snapshot (if a policy is configured).
    pub fn policy_snapshot(&self) -> Option<PolicySnapshot> {
        self.policy.as_ref().map(|p| p.to_snapshot())
    }

    /// Check if a tool is allowed by the policy. Returns violations if any.
    pub fn check_tool(&self, tool_name: &str) -> (bool, Vec<String>) {
        let Some(ref policy) = self.policy else {
            return (true, Vec::new());
        };

        let mut violations = Vec::new();

        if let Some(allowed) = policy.is_tool_allowed(tool_name) {
            if !allowed {
                violations.push("tool_not_in_allowlist".to_string());
            }
        }

        (violations.is_empty(), violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_priority_config_over_handshake() {
        let config_id = AgentIdentity::from_mcp_client_info("config-agent", None);
        let mut session = McpSession::new(Some(config_id), None);

        // Even after handshake, config identity takes priority
        session.on_initialize_request(&serde_json::json!({
            "clientInfo": {"name": "handshake-agent", "version": "1.0"}
        }));

        assert_eq!(session.identity().name, "config-agent");
    }

    #[test]
    fn identity_falls_back_to_handshake() {
        let mut session = McpSession::new(None, None);
        session.on_initialize_request(&serde_json::json!({
            "clientInfo": {"name": "claude-desktop", "version": "2.0"}
        }));

        let id = session.identity();
        assert_eq!(id.name, "claude-desktop");
        assert_eq!(id.version.as_deref(), Some("2.0"));
    }

    #[test]
    fn identity_falls_back_to_environment() {
        let session = McpSession::new(None, None);
        let id = session.identity();
        // Should not panic, name should be populated from env
        assert!(!id.name.is_empty());
    }

    #[test]
    fn captures_server_info() {
        let mut session = McpSession::new(None, None);
        assert!(!session.initialized);

        session.on_initialize_response(&serde_json::json!({
            "serverInfo": {"name": "postgres-mcp", "version": "0.3"},
            "capabilities": {"tools": {"listChanged": true}, "logging": {}}
        }));

        assert!(session.initialized);
        assert_eq!(session.server_info.as_ref().unwrap()["name"], "postgres-mcp");
        assert!(session.server_capabilities.is_some());
    }

    #[test]
    fn tool_check_no_policy() {
        let session = McpSession::new(None, None);
        let (allowed, violations) = session.check_tool("anything");
        assert!(allowed);
        assert!(violations.is_empty());
    }

    #[test]
    fn tool_check_with_allowlist() {
        let policy = PolicyConfig {
            policies: vec![manifest_core::PolicyRule::ToolAllowlist {
                allowed_tools: vec!["db_query".into()],
            }],
        };
        let session = McpSession::new(None, Some(policy));

        let (allowed, _) = session.check_tool("db_query");
        assert!(allowed);

        let (allowed, violations) = session.check_tool("drop_table");
        assert!(!allowed);
        assert!(violations.contains(&"tool_not_in_allowlist".to_string()));
    }
}
