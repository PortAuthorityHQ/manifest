use regex::Regex;
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

    /// Regex-based PII detection with built-in patterns.
    ///
    /// Supports custom regex patterns and/or built-in detectors for
    /// common PII types: `ssn`, `credit_card`, `email`, `phone`.
    #[serde(rename = "pii-regex")]
    PiiRegex {
        /// Built-in pattern names to enable (e.g., ["ssn", "credit_card", "email"]).
        #[serde(default)]
        builtin: Vec<String>,

        /// Custom regex patterns with labels (e.g., {"passport": "\\b[A-Z]\\d{8}\\b"}).
        #[serde(default)]
        custom: std::collections::HashMap<String, String>,
    },
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
                PolicyRule::PiiFlag { .. } | PolicyRule::PiiRegex { .. } => {
                    // PII rules don't appear in the snapshot — they're evaluated at check time
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

    /// Evaluate all policy rules against a tool call.
    ///
    /// Returns a list of violation strings. An empty list means the action
    /// is fully authorized.
    pub fn evaluate(
        &self,
        tool_name: &str,
        input: &serde_json::Value,
        output: Option<&serde_json::Value>,
    ) -> Vec<String> {
        let mut violations = Vec::new();

        for rule in &self.policies {
            match rule {
                PolicyRule::ToolAllowlist { allowed_tools } => {
                    if !allowed_tools.iter().any(|t| t == tool_name) {
                        violations.push(format!(
                            "tool_not_in_allowlist: '{tool_name}' not in [{}]",
                            allowed_tools.join(", ")
                        ));
                    }
                }
                PolicyRule::SpendingLimit {
                    max_transaction_value,
                } => {
                    for value in extract_numeric_values(input) {
                        if value > *max_transaction_value as f64 {
                            violations.push(format!(
                                "spending_limit_exceeded: value {value} exceeds max {max_transaction_value}"
                            ));
                        }
                    }
                }
                PolicyRule::PiiFlag { flag_if_contains } => {
                    let input_str = input.to_string().to_lowercase();
                    for pattern in flag_if_contains {
                        let pattern_lower = pattern.to_lowercase();
                        if input_str.contains(&pattern_lower) {
                            violations.push(format!("pii_detected_in_input: '{pattern}'"));
                        }
                    }

                    if let Some(out) = output {
                        let output_str = out.to_string().to_lowercase();
                        for pattern in flag_if_contains {
                            let pattern_lower = pattern.to_lowercase();
                            if output_str.contains(&pattern_lower) {
                                violations.push(format!("pii_detected_in_output: '{pattern}'"));
                            }
                        }
                    }
                }
                PolicyRule::PiiRegex { builtin, custom } => {
                    let mut patterns: Vec<(String, Regex)> = Vec::new();

                    // Load built-in patterns
                    for name in builtin {
                        if let Some(re) = builtin_pii_regex(name) {
                            patterns.push((name.clone(), re));
                        }
                        // Unknown built-in names are silently skipped
                    }

                    // Load custom patterns
                    for (label, pattern) in custom {
                        if let Ok(re) = Regex::new(pattern) {
                            patterns.push((label.clone(), re));
                        }
                        // Invalid regex patterns are silently skipped
                    }

                    let input_str = input.to_string();
                    for (label, re) in &patterns {
                        if re.is_match(&input_str) {
                            violations.push(format!("pii_regex_match_in_input: '{label}'"));
                        }
                    }

                    if let Some(out) = output {
                        let output_str = out.to_string();
                        for (label, re) in &patterns {
                            if re.is_match(&output_str) {
                                violations.push(format!("pii_regex_match_in_output: '{label}'"));
                            }
                        }
                    }
                }
            }
        }

        violations
    }
}

/// Recursively extract all numeric values from a JSON value.
fn extract_numeric_values(value: &serde_json::Value) -> Vec<f64> {
    let mut values = Vec::new();
    match value {
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                values.push(f);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                values.extend(extract_numeric_values(v));
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                values.extend(extract_numeric_values(v));
            }
        }
        _ => {}
    }
    values
}

/// Get a built-in regex pattern for a named PII type.
///
/// Supported names:
/// - `ssn` — US Social Security Number (XXX-XX-XXXX)
/// - `credit_card` — Major credit card numbers (13-19 digits, common prefixes)
/// - `email` — Email addresses
/// - `phone` — US phone numbers (various formats)
fn builtin_pii_regex(name: &str) -> Option<Regex> {
    let pattern = match name {
        "ssn" => r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card" => r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b",
        "email" => r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phone" => r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        _ => return None,
    };
    Regex::new(pattern).ok()
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
    fn evaluate_spending_limit_violation() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::SpendingLimit {
                max_transaction_value: 10000,
            }],
        };

        let input = serde_json::json!({"amount": 50000, "currency": "USD"});
        let violations = config.evaluate("transfer", &input, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("spending_limit_exceeded"));
        assert!(violations[0].contains("50000"));
    }

    #[test]
    fn evaluate_spending_limit_nested() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::SpendingLimit {
                max_transaction_value: 1000,
            }],
        };

        let input = serde_json::json!({
            "order": {
                "items": [{"price": 500}, {"price": 2000}]
            }
        });
        let violations = config.evaluate("checkout", &input, None);
        // Only the 2000 value exceeds the limit
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("2000"));
    }

    #[test]
    fn evaluate_spending_limit_passes() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::SpendingLimit {
                max_transaction_value: 10000,
            }],
        };

        let input = serde_json::json!({"amount": 500});
        let violations = config.evaluate("transfer", &input, None);
        assert!(violations.is_empty());
    }

    #[test]
    fn evaluate_pii_in_input() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiFlag {
                flag_if_contains: vec!["SSN".into(), "credit_card".into()],
            }],
        };

        let input = serde_json::json!({"query": "SELECT ssn FROM users"});
        let violations = config.evaluate("db_query", &input, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("pii_detected_in_input"));
        assert!(violations[0].contains("SSN"));
    }

    #[test]
    fn evaluate_pii_in_output() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiFlag {
                flag_if_contains: vec!["credit_card".into()],
            }],
        };

        let input = serde_json::json!({"query": "SELECT * FROM payments"});
        let output = serde_json::json!({"rows": [{"credit_card": "4111-1111-1111"}]});
        let violations = config.evaluate("db_query", &input, Some(&output));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("pii_detected_in_output"));
    }

    #[test]
    fn evaluate_no_pii() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiFlag {
                flag_if_contains: vec!["SSN".into()],
            }],
        };

        let input = serde_json::json!({"query": "SELECT name FROM users"});
        let violations = config.evaluate("db_query", &input, None);
        assert!(violations.is_empty());
    }

    #[test]
    fn evaluate_multiple_rules() {
        let config = PolicyConfig {
            policies: vec![
                PolicyRule::ToolAllowlist {
                    allowed_tools: vec!["db_query".into()],
                },
                PolicyRule::SpendingLimit {
                    max_transaction_value: 1000,
                },
                PolicyRule::PiiFlag {
                    flag_if_contains: vec!["SSN".into()],
                },
            ],
        };

        // Disallowed tool, high value, and PII
        let input = serde_json::json!({"amount": 5000, "field": "ssn"});
        let violations = config.evaluate("transfer", &input, None);
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn evaluate_pii_regex_ssn() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiRegex {
                builtin: vec!["ssn".into()],
                custom: std::collections::HashMap::new(),
            }],
        };

        // Actual SSN format triggers
        let input = serde_json::json!({"data": "SSN is 123-45-6789"});
        let violations = config.evaluate("query", &input, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("pii_regex_match_in_input"));
        assert!(violations[0].contains("ssn"));
    }

    #[test]
    fn evaluate_pii_regex_no_false_positive() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiRegex {
                builtin: vec!["ssn".into()],
                custom: std::collections::HashMap::new(),
            }],
        };

        // The word "assign" contains "ssn" as a substring but should NOT trigger
        // the regex detector (unlike the naive string-match PiiFlag)
        let input = serde_json::json!({"action": "assign task to user"});
        let violations = config.evaluate("task", &input, None);
        assert!(violations.is_empty(), "regex should not match 'assign'");
    }

    #[test]
    fn evaluate_pii_regex_credit_card() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiRegex {
                builtin: vec!["credit_card".into()],
                custom: std::collections::HashMap::new(),
            }],
        };

        let input = serde_json::json!({"card": "4111111111111111"});
        let violations = config.evaluate("payment", &input, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("credit_card"));
    }

    #[test]
    fn evaluate_pii_regex_email() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiRegex {
                builtin: vec!["email".into()],
                custom: std::collections::HashMap::new(),
            }],
        };

        let output = serde_json::json!({"result": "Contact: user@example.com"});
        let input = serde_json::json!({});
        let violations = config.evaluate("query", &input, Some(&output));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("pii_regex_match_in_output"));
    }

    #[test]
    fn evaluate_pii_regex_custom() {
        let mut custom = std::collections::HashMap::new();
        custom.insert("passport".into(), r"\b[A-Z]\d{8}\b".into());

        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiRegex {
                builtin: vec![],
                custom,
            }],
        };

        let input = serde_json::json!({"doc": "Passport: A12345678"});
        let violations = config.evaluate("verify", &input, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("passport"));
    }

    #[test]
    fn evaluate_pii_regex_phone() {
        let config = PolicyConfig {
            policies: vec![PolicyRule::PiiRegex {
                builtin: vec!["phone".into()],
                custom: std::collections::HashMap::new(),
            }],
        };

        let input = serde_json::json!({"contact": "Call (555) 123-4567"});
        let violations = config.evaluate("lookup", &input, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("phone"));
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
