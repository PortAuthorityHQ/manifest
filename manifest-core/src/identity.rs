use serde::{Deserialize, Serialize};

use crate::error::ManifestError;

/// How the agent identity was determined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// Auto-extracted from the MCP `initialize` handshake.
    McpHandshake,
    /// Declared in a config file.
    Config,
    /// Inferred from the runtime environment.
    Environment,
}

/// Agent identity included in every receipt.
///
/// In the open-source version, identity is self-declared (`verified: false`).
/// The schema is designed so that upgrading to verified identity (e.g. SPIFFE)
/// requires no receipt format change — just flipping `verified` to `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub source: IdentitySource,
    pub verified: bool,
}

/// YAML config file structure for explicit identity declaration.
#[derive(Debug, Deserialize)]
struct IdentityConfigFile {
    agent: IdentityConfigAgent,
}

#[derive(Debug, Deserialize)]
struct IdentityConfigAgent {
    name: String,
    deployer: Option<String>,
    environment: Option<String>,
}

impl AgentIdentity {
    /// Build identity from MCP `initialize` handshake `clientInfo`.
    pub fn from_mcp_client_info(name: &str, version: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            version: version.map(String::from),
            deployer: None,
            environment: None,
            source: IdentitySource::McpHandshake,
            verified: false,
        }
    }

    /// Build identity from a YAML config file.
    pub fn from_config_file(path: &std::path::Path) -> Result<Self, ManifestError> {
        let contents = std::fs::read_to_string(path)?;
        let config: IdentityConfigFile = serde_yaml::from_str(&contents)?;
        Ok(Self {
            name: config.agent.name,
            version: None,
            deployer: config.agent.deployer,
            environment: config.agent.environment,
            source: IdentitySource::Config,
            verified: false,
        })
    }

    /// Build identity from the runtime environment (process name, hostname).
    pub fn from_environment() -> Self {
        let name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "unknown".to_string());

        let deployer = hostname::get()
            .ok()
            .map(|h| h.to_string_lossy().into_owned());

        Self {
            name,
            version: None,
            deployer,
            environment: std::env::var("MANIFEST_ENV").ok(),
            source: IdentitySource::Environment,
            verified: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_mcp_client_info() {
        let id = AgentIdentity::from_mcp_client_info("claude-desktop", Some("1.2.0"));
        assert_eq!(id.name, "claude-desktop");
        assert_eq!(id.version.as_deref(), Some("1.2.0"));
        assert_eq!(id.source, IdentitySource::McpHandshake);
        assert!(!id.verified);
    }

    #[test]
    fn from_environment() {
        let id = AgentIdentity::from_environment();
        assert!(!id.name.is_empty());
        assert_eq!(id.source, IdentitySource::Environment);
        assert!(!id.verified);
    }

    #[test]
    fn from_config_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("identity.yml");
        std::fs::write(
            &path,
            r#"
agent:
  name: "procurement-bot"
  deployer: "acme-corp"
  environment: "production"
"#,
        )
        .unwrap();

        let id = AgentIdentity::from_config_file(&path).unwrap();
        assert_eq!(id.name, "procurement-bot");
        assert_eq!(id.deployer.as_deref(), Some("acme-corp"));
        assert_eq!(id.environment.as_deref(), Some("production"));
        assert_eq!(id.source, IdentitySource::Config);
    }

    #[test]
    fn serializes_to_json() {
        let id = AgentIdentity::from_mcp_client_info("test-agent", None);
        let json = serde_json::to_value(&id).unwrap();
        assert_eq!(json["source"], "mcp_handshake");
        assert_eq!(json["verified"], false);
        // version is None so it should be omitted
        assert!(json.get("version").is_none());
    }
}
