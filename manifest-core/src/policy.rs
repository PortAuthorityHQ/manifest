use serde::{Deserialize, Serialize};

use crate::error::ManifestError;
use crate::hashing::sha256_hex;

/// A snapshot of the active policy at the time of a tool call, embedded in the receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    #[serde(rename = "maxTransactionValue", skip_serializing_if = "Option::is_none")]
    pub max_transaction_value: Option<u64>,

    #[serde(rename = "allowedTools", skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,

    /// SHA-256 hash of the policy config at the time of the call.
    pub snapshot: String,
}

/// Top-level policy configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policies: Vec<PolicyRule>,
}

/// Individual policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "name")]
pub enum PolicyRule {
    #[serde(rename = "spending-limit")]
    SpendingLimit { max_transaction_value: u64 },

    #[serde(rename = "tool-allowlist")]
    ToolAllowlist { allowed_tools: Vec<String> },

    #[serde(rename = "pii-flag")]
    PiiFlag { flag_if_contains: Vec<String> },
}

impl PolicyConfig {
    /// Load policy configuration from a YAML file.
    pub fn load(path: &std::path::Path) -> Result<Self, ManifestError> {
        let contents = std::fs::read_to_string(path)?;
        let config: PolicyConfig = serde_yaml::from_str(&contents)?;
        Ok(config)
    }

    /// Compute a deterministic SHA-256 hash of this policy configuration.
    pub fn snapshot_hash(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        sha256_hex(canonical.as_bytes())
    }

    /// Convert to a PolicySnapshot for embedding in receipts.
    pub fn to_snapshot(&self) -> PolicySnapshot {
        let mut max_value = None;
        let mut allowed = None;

        for rule in &self.policies {
            match rule {
                PolicyRule::SpendingLimit { max_transaction_value } => {
                    max_value = Some(*max_transaction_value);
                }
                PolicyRule::ToolAllowlist { allowed_tools } => {
                    allowed = Some(allowed_tools.clone());
                }
                PolicyRule::PiiFlag { .. } => {
                    // PII flags don't appear in the snapshot — they're evaluated at check time
                }
            }
        }

        PolicySnapshot {
            max_transaction_value: max_value,
            allowed_tools: allowed,
            snapshot: self.snapshot_hash(),
        }
    }

    /// Check if a tool name is allowed by the allowlist policy.
    /// Returns None if no allowlist is configured (all tools allowed).
    pub fn is_tool_allowed(&self, tool_name: &str) -> Option<bool> {
        for rule in &self.policies {
            if let PolicyRule::ToolAllowlist { allowed_tools } = rule {
                return Some(allowed_tools.iter().any(|t| t == tool_name));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_policy_from_yaml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("policy.yml");
        std::fs::write(
            &path,
            r#"
policies:
  - name: spending-limit
    max_transaction_value: 50000
  - name: tool-allowlist
    allowed_tools:
      - db_query
      - send_email
  - name: pii-flag
    flag_if_contains:
      - SSN
      - credit_card
"#,
        )
        .unwrap();

        let config = PolicyConfig::load(&path).unwrap();
        assert_eq!(config.policies.len(), 3);
    }

    #[test]
    fn policy_snapshot() {
        let config = PolicyConfig {
            policies: vec![
                PolicyRule::SpendingLimit {
                    max_transaction_value: 10000,
                },
                PolicyRule::ToolAllowlist {
                    allowed_tools: vec!["read_file".into()],
                },
            ],
        };

        let snapshot = config.to_snapshot();
        assert_eq!(snapshot.max_transaction_value, Some(10000));
        assert_eq!(snapshot.allowed_tools, Some(vec!["read_file".to_string()]));
        assert!(snapshot.snapshot.starts_with("sha256:"));
    }

    #[test]
    fn tool_allowlist_check() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::ToolAllowlist {
                allowed_tools: vec!["db_query".into(), "send_email".into()],
            }],
        };

        assert_eq!(config.is_tool_allowed("db_query"), Some(true));
        assert_eq!(config.is_tool_allowed("drop_table"), Some(false));
    }

    #[test]
    fn no_allowlist_returns_none() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::SpendingLimit {
                max_transaction_value: 5000,
            }],
        };
        assert_eq!(config.is_tool_allowed("anything"), None);
    }

    #[test]
    fn snapshot_hash_is_deterministic() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::SpendingLimit {
                max_transaction_value: 100,
            }],
        };
        assert_eq!(config.snapshot_hash(), config.snapshot_hash());
    }
}
