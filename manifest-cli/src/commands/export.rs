use std::collections::HashSet;

use manifest_core::{ManifestError, Receipt, Storage, StorageBackend};

use crate::commands::init::resolve_db_path;

/// Export receipts as JSON, JSONL, or HTML.
///
/// Optionally sends each receipt to an HTTP sink for SIEM ingestion.
pub async fn run(
    session: Option<&str>,
    format: &str,
    output: Option<&str>,
    db: Option<&str>,
    sink_url: Option<&str>,
    sink_token: Option<&str>,
    sink_format: &str,
) -> Result<(), ManifestError> {
    let db_path = resolve_db_path(db);

    if !db_path.exists() {
        return Err(ManifestError::NotFound(
            "no receipt database found".to_string(),
        ));
    }

    let storage = Storage::open(&db_path)?;

    let receipts = match session {
        Some(sid) => storage.list_by_session(sid, usize::MAX, 0)?,
        None => storage.list_receipts(usize::MAX, 0)?,
    };

    let content = match format {
        "json" => serde_json::to_string_pretty(&receipts)?,
        "jsonl" => receipts
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n"),
        "html" => render_html(&receipts),
        other => {
            return Err(ManifestError::Config(format!(
                "unsupported format: '{other}'. Use 'json', 'jsonl', or 'html'."
            )));
        }
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            eprintln!(
                "Exported {} receipt(s) to {}",
                receipts.len(),
                path
            );
        }
        None => {
            print!("{content}");
        }
    }

    // Batch export to SIEM sink if configured
    if let Some(url) = sink_url {
        let client = reqwest::Client::new();
        let mut success = 0usize;
        let mut failed = 0usize;

        for receipt in &receipts {
            let payload = if sink_format == "splunk-hec" {
                serde_json::json!({
                    "event": receipt,
                    "sourcetype": "manifest:receipt",
                    "source": "manifest-export",
                })
            } else {
                serde_json::to_value(receipt).unwrap_or_default()
            };

            let mut req = client.post(url).json(&payload);
            if let Some(token) = sink_token {
                req = req.header("Authorization", format!("Bearer {token}"));
            }

            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    success += 1;
                }
                Ok(resp) => {
                    eprintln!(
                        "Sink returned {} for receipt {}",
                        resp.status(),
                        receipt.id
                    );
                    failed += 1;
                }
                Err(e) => {
                    eprintln!("Sink error for receipt {}: {e}", receipt.id);
                    failed += 1;
                }
            }
        }

        eprintln!("Sink export: {success} sent, {failed} failed");
    }

    Ok(())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn truncate_hash(hash: &str, len: usize) -> String {
    if hash.len() > len {
        format!("{}…", &hash[..len])
    } else {
        hash.to_string()
    }
}

fn render_html(receipts: &[Receipt]) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let total = receipts.len();

    let violation_count = receipts
        .iter()
        .filter(|r| {
            r.delta
                .as_ref()
                .map(|d| !d.violations.is_empty())
                .unwrap_or(false)
        })
        .count();

    let tools: HashSet<&str> = receipts.iter().map(|r| r.action.tool.as_str()).collect();
    let agents: HashSet<&str> = receipts.iter().map(|r| r.agent.name.as_str()).collect();

    let mut html = String::with_capacity(64 * 1024);

    // Header
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Manifest — Agent Activity Report</title>
<style>
:root {{
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --text-muted: #8b949e;
  --green: #3fb950;
  --green-bg: #0d2818;
  --red: #f85149;
  --red-bg: #3d1214;
  --yellow: #d29922;
  --yellow-bg: #2d2000;
  --blue: #58a6ff;
  --purple: #bc8cff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  padding: 32px;
  max-width: 1200px;
  margin: 0 auto;
}}
h1 {{
  font-size: 24px;
  font-weight: 600;
  margin-bottom: 4px;
}}
.subtitle {{
  color: var(--text-muted);
  font-size: 13px;
  margin-bottom: 24px;
}}
.stats {{
  display: flex;
  gap: 16px;
  margin-bottom: 32px;
  flex-wrap: wrap;
}}
.stat {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 24px;
  min-width: 140px;
}}
.stat-value {{
  font-size: 28px;
  font-weight: 700;
  line-height: 1.2;
}}
.stat-value.violations {{ color: var(--red); }}
.stat-label {{
  color: var(--text-muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
.receipt {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
  overflow: hidden;
}}
.receipt-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 20px;
  flex-wrap: wrap;
}}
.receipt-header .time {{
  color: var(--text-muted);
  font-size: 13px;
  font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
  min-width: 160px;
}}
.receipt-header .tool {{
  font-weight: 600;
  font-size: 15px;
  color: var(--blue);
}}
.receipt-header .agent {{
  color: var(--purple);
  font-size: 13px;
}}
.badge {{
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}
.badge-ok {{
  background: var(--green-bg);
  color: var(--green);
  border: 1px solid #1a4d2e;
}}
.badge-violation {{
  background: var(--red-bg);
  color: var(--red);
  border: 1px solid #5c1d1f;
}}
.badge-denied {{
  background: var(--yellow-bg);
  color: var(--yellow);
  border: 1px solid #4d3800;
}}
.badge-none {{
  background: var(--surface);
  color: var(--text-muted);
  border: 1px solid var(--border);
}}
.badge-error {{
  background: var(--red-bg);
  color: var(--red);
  border: 1px solid #5c1d1f;
}}
.violations-list {{
  padding: 0 20px 12px 20px;
}}
.violation-item {{
  color: var(--red);
  font-size: 13px;
  padding: 2px 0;
}}
.violation-item::before {{
  content: "⚠ ";
}}
details {{
  border-top: 1px solid var(--border);
}}
summary {{
  padding: 10px 20px;
  cursor: pointer;
  color: var(--text-muted);
  font-size: 13px;
  user-select: none;
}}
summary:hover {{
  color: var(--text);
}}
.detail-body {{
  padding: 0 20px 16px 20px;
}}
pre {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
  font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text);
}}
.proof-grid {{
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 4px 16px;
  font-size: 12px;
  font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
}}
.proof-label {{
  color: var(--text-muted);
}}
.proof-value {{
  color: var(--text);
  word-break: break-all;
}}
.error-box {{
  background: var(--red-bg);
  border: 1px solid #5c1d1f;
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 12px;
}}
.error-code {{
  color: var(--red);
  font-weight: 600;
  font-size: 13px;
}}
.error-msg {{
  color: var(--text);
  font-size: 13px;
}}
.footer {{
  text-align: center;
  color: var(--text-muted);
  font-size: 12px;
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
}}
.footer a {{ color: var(--blue); text-decoration: none; }}
.source-badge {{
  font-size: 11px;
  color: var(--text-muted);
  background: var(--bg);
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid var(--border);
}}
.spacer {{ flex: 1; }}
.hash {{
  color: var(--text-muted);
  font-size: 12px;
  font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
}}
</style>
</head>
<body>
<h1>Manifest — Agent Activity Report</h1>
<p class="subtitle">Generated {now} · {total} receipt(s)</p>

<div class="stats">
  <div class="stat">
    <div class="stat-value">{total}</div>
    <div class="stat-label">Receipts</div>
  </div>
  <div class="stat">
    <div class="stat-value violations">{violation_count}</div>
    <div class="stat-label">Violations</div>
  </div>
  <div class="stat">
    <div class="stat-value">{tools}</div>
    <div class="stat-label">Tools</div>
  </div>
  <div class="stat">
    <div class="stat-value">{agents}</div>
    <div class="stat-label">Agents</div>
  </div>
</div>
"#,
        now = now,
        total = total,
        violation_count = violation_count,
        tools = tools.len(),
        agents = agents.len(),
    ));

    // Receipts in chronological order (list_receipts returns newest first)
    for receipt in receipts.iter().rev() {
        let timestamp = receipt.timestamp.format("%Y-%m-%d %H:%M:%S");
        let tool = escape_html(&receipt.action.tool);
        let agent = escape_html(&receipt.agent.name);
        let source = format!("{:?}", receipt.agent.source).to_lowercase();
        let content_hash = receipt.content_hash();
        let hash_short = truncate_hash(&content_hash, 24);

        // Status badge
        let (badge_class, badge_text) = if let Some(ref delta) = receipt.delta {
            if !delta.violations.is_empty() {
                ("badge-violation", "VIOLATION")
            } else if delta.authorized {
                ("badge-ok", "AUTHORIZED")
            } else {
                ("badge-denied", "DENIED")
            }
        } else {
            ("badge-none", "NO POLICY")
        };

        html.push_str(&format!(
            r#"<div class="receipt">
  <div class="receipt-header">
    <span class="time">{timestamp}</span>
    <span class="tool">{tool}</span>
    <span class="agent">{agent}</span>
    <span class="source-badge">{source}</span>
    <span class="badge {badge_class}">{badge_text}</span>
    <span class="spacer"></span>
    <span class="hash">{hash_short}</span>
  </div>
"#,
        ));

        // Violations
        if let Some(ref delta) = receipt.delta {
            if !delta.violations.is_empty() {
                html.push_str("  <div class=\"violations-list\">\n");
                for v in &delta.violations {
                    html.push_str(&format!(
                        "    <div class=\"violation-item\">{}</div>\n",
                        escape_html(v)
                    ));
                }
                html.push_str("  </div>\n");
            }
        }

        // Error (if any)
        if let Some(ref error) = receipt.action.error {
            html.push_str(&format!(
                r#"  <div class="detail-body">
    <div class="error-box">
      <div class="error-code">Error {code}</div>
      <div class="error-msg">{message}</div>
    </div>
  </div>
"#,
                code = error.code,
                message = escape_html(&error.message),
            ));
        }

        // Input/Output details
        let input_json = escape_html(
            &serde_json::to_string_pretty(&receipt.action.input).unwrap_or_default(),
        );
        html.push_str(&format!(
            r#"  <details>
    <summary>Input</summary>
    <div class="detail-body">
      <pre>{input_json}</pre>
    </div>
  </details>
"#,
        ));

        if let Some(ref output) = receipt.action.output {
            let output_json =
                escape_html(&serde_json::to_string_pretty(output).unwrap_or_default());
            html.push_str(&format!(
                r#"  <details>
    <summary>Output</summary>
    <div class="detail-body">
      <pre>{output_json}</pre>
    </div>
  </details>
"#,
            ));
        }

        // Proof details
        let sig_short = truncate_hash(&receipt.proof.signature, 32);
        let merkle_short = truncate_hash(&receipt.proof.merkle_root, 32);
        let prev = receipt
            .proof
            .previous_receipt
            .as_deref()
            .map(|h| truncate_hash(h, 32))
            .unwrap_or_else(|| "—".to_string());

        html.push_str(&format!(
            r#"  <details>
    <summary>Proof</summary>
    <div class="detail-body">
      <div class="proof-grid">
        <span class="proof-label">signature</span>
        <span class="proof-value">{sig}</span>
        <span class="proof-label">merkle root</span>
        <span class="proof-value">{merkle}</span>
        <span class="proof-label">previous</span>
        <span class="proof-value">{prev}</span>
        <span class="proof-label">content hash</span>
        <span class="proof-value">{hash}</span>
      </div>
    </div>
  </details>
"#,
            sig = escape_html(&sig_short),
            merkle = escape_html(&merkle_short),
            prev = escape_html(&prev),
            hash = escape_html(&content_hash),
        ));

        html.push_str("</div>\n\n");
    }

    // Footer
    html.push_str(
        r#"<div class="footer">
  Generated by <strong>Manifest</strong> · Cryptographic receipts for AI agent tool calls<br>
  <a href="https://github.com/PortAuthorityHQ/manifest">github.com/PortAuthorityHQ/manifest</a>
</div>
</body>
</html>
"#,
    );

    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifest_core::receipt::Delta;
    use manifest_core::{
        Action, ActionError, AgentIdentity, IdentitySource, MerkleTree, ReceiptBuilder, Signer,
    };

    // --- escape_html tests ---

    #[test]
    fn escape_html_individual_chars() {
        assert_eq!(escape_html("<"), "&lt;");
        assert_eq!(escape_html(">"), "&gt;");
        assert_eq!(escape_html("&"), "&amp;");
        assert_eq!(escape_html("\""), "&quot;");
        assert_eq!(escape_html("'"), "&#39;");
    }

    #[test]
    fn escape_html_script_injection() {
        assert_eq!(
            escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn escape_html_attribute_breaking() {
        assert_eq!(
            escape_html("\" onclick=\"alert(1)"),
            "&quot; onclick=&quot;alert(1)"
        );
    }

    #[test]
    fn escape_html_ampersand_ordering() {
        // & must be escaped first to avoid double-escaping
        assert_eq!(escape_html("&lt;"), "&amp;lt;");
        assert_eq!(escape_html("&amp;"), "&amp;amp;");
    }

    #[test]
    fn escape_html_passthrough() {
        assert_eq!(escape_html("normal text 123"), "normal text 123");
        assert_eq!(escape_html(""), "");
        assert_eq!(escape_html("hello world"), "hello world");
    }

    // --- render_html tests ---

    fn make_test_receipt(violations: Vec<String>) -> Receipt {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        ReceiptBuilder::new()
            .agent(AgentIdentity {
                name: "test-agent".into(),
                version: Some("1.0".into()),
                deployer: None,
                environment: None,
                source: IdentitySource::Environment,
                verified: false,
            })
            .action(Action {
                tool: "test_tool".into(),
                input: serde_json::json!({"query": "SELECT 1"}),
                output: Some(serde_json::json!({"rows": 1})),
                error: None,
            })
            .delta(Some(Delta {
                authorized: violations.is_empty(),
                violations,
            }))
            .build(&signer, &mut merkle)
            .unwrap()
    }

    #[test]
    fn render_html_valid_structure() {
        let html = render_html(&[make_test_receipt(vec![])]);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<title>Manifest — Agent Activity Report</title>"));
        assert!(html.contains("</body>"));
    }

    #[test]
    fn render_html_xss_in_violations() {
        let html = render_html(&[make_test_receipt(vec![
            "<script>alert('xss')</script>".into(),
        ])]);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn render_html_violation_badge() {
        let html = render_html(&[make_test_receipt(vec!["spending limit exceeded".into()])]);
        assert!(html.contains("badge-violation"));
        assert!(html.contains("VIOLATION"));
        assert!(html.contains("spending limit exceeded"));
    }

    #[test]
    fn render_html_authorized_badge() {
        let html = render_html(&[make_test_receipt(vec![])]);
        assert!(html.contains("badge-ok"));
        assert!(html.contains("AUTHORIZED"));
    }

    #[test]
    fn render_html_xss_in_tool_and_agent_names() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(AgentIdentity {
                name: "<img src=x onerror=alert(1)>".into(),
                version: None,
                deployer: None,
                environment: None,
                source: IdentitySource::Environment,
                verified: false,
            })
            .action(Action {
                tool: "<script>steal()</script>".into(),
                input: serde_json::json!({}),
                output: None,
                error: None,
            })
            .build(&signer, &mut merkle)
            .unwrap();

        let html = render_html(&[receipt]);
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<script>steal"));
        assert!(html.contains("&lt;img src=x"));
        assert!(html.contains("&lt;script&gt;steal"));
    }

    #[test]
    fn render_html_error_box() {
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = ReceiptBuilder::new()
            .agent(AgentIdentity {
                name: "test".into(),
                version: None,
                deployer: None,
                environment: None,
                source: IdentitySource::Environment,
                verified: false,
            })
            .action(Action {
                tool: "failing_tool".into(),
                input: serde_json::json!({}),
                output: None,
                error: Some(ActionError {
                    code: -32603,
                    message: "Internal error <malicious>".into(),
                    data: None,
                }),
            })
            .build(&signer, &mut merkle)
            .unwrap();

        let html = render_html(&[receipt]);
        assert!(html.contains("error-box"));
        assert!(html.contains("Error -32603"));
        assert!(html.contains("&lt;malicious&gt;"));
        assert!(!html.contains("<malicious>"));
    }

    #[test]
    fn render_html_summary_stats() {
        let receipts = vec![
            make_test_receipt(vec!["violation 1".into()]),
            make_test_receipt(vec![]),
            make_test_receipt(vec![]),
        ];
        let html = render_html(&receipts);

        // 3 total receipts
        assert!(html.contains("<div class=\"stat-value\">3</div>"));
        // 1 violation
        assert!(html.contains("<div class=\"stat-value violations\">1</div>"));
    }
}
