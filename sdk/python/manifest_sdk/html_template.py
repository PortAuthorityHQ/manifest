"""HTML export template matching the Rust CLI's dark-theme report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .receipt import Receipt


def escape_html(s: str) -> str:
    """Escape HTML special characters to prevent XSS."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _truncate(s: str, length: int) -> str:
    if len(s) > length:
        return s[:length] + "\u2026"
    return s


def render_html(receipts: list[Receipt]) -> str:
    """Render receipts as a self-contained HTML report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(receipts)

    violation_count = sum(
        1
        for r in receipts
        if r.delta and r.delta.violations
    )

    tools = set(r.action.tool for r in receipts)
    agents = set(r.agent.name for r in receipts)
    tool_count = len(tools)
    agent_count = len(agents)

    parts: list[str] = []

    parts.append(f'''<!DOCTYPE html>
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
.violations-list {{
  padding: 0 20px 12px 20px;
}}
.violation-item {{
  color: var(--red);
  font-size: 13px;
  padding: 2px 0;
}}
.violation-item::before {{
  content: "\u26a0 ";
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
    <div class="stat-value">{tool_count}</div>
    <div class="stat-label">Tools</div>
  </div>
  <div class="stat">
    <div class="stat-value">{agent_count}</div>
    <div class="stat-label">Agents</div>
  </div>
</div>
''')

    # Receipts in chronological order (list comes newest first, so reverse)
    for receipt in reversed(receipts):
        timestamp = receipt.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        tool = escape_html(receipt.action.tool)
        agent = escape_html(receipt.agent.name)
        source = str(receipt.agent.source.value if hasattr(receipt.agent.source, 'value') else receipt.agent.source).lower()
        content_hash = receipt.content_hash()
        hash_short = _truncate(content_hash, 24)

        if receipt.delta:
            if receipt.delta.violations:
                badge_class, badge_text = "badge-violation", "VIOLATION"
            elif receipt.delta.authorized:
                badge_class, badge_text = "badge-ok", "AUTHORIZED"
            else:
                badge_class, badge_text = "badge-denied", "DENIED"
        else:
            badge_class, badge_text = "badge-none", "NO POLICY"

        parts.append(f'''<div class="receipt">
  <div class="receipt-header">
    <span class="time">{timestamp}</span>
    <span class="tool">{tool}</span>
    <span class="agent">{agent}</span>
    <span class="source-badge">{escape_html(source)}</span>
    <span class="badge {badge_class}">{badge_text}</span>
    <span class="spacer"></span>
    <span class="hash">{escape_html(hash_short)}</span>
  </div>
''')

        # Violations
        if receipt.delta and receipt.delta.violations:
            parts.append('  <div class="violations-list">\n')
            for v in receipt.delta.violations:
                parts.append(f'    <div class="violation-item">{escape_html(v)}</div>\n')
            parts.append('  </div>\n')

        # Error
        if receipt.action.error:
            parts.append(f'''  <div class="detail-body">
    <div class="error-box">
      <div class="error-code">Error {receipt.action.error.code}</div>
      <div class="error-msg">{escape_html(receipt.action.error.message)}</div>
    </div>
  </div>
''')

        # Input
        rd = receipt.to_dict() if hasattr(receipt, 'to_dict') else {}
        input_json = escape_html(json.dumps(rd.get("action", {}).get("input", {}), indent=2))
        parts.append(f'''  <details>
    <summary>Input</summary>
    <div class="detail-body">
      <pre>{input_json}</pre>
    </div>
  </details>
''')

        # Output
        action_output = rd.get("action", {}).get("output")
        if action_output is not None:
            output_json = escape_html(json.dumps(action_output, indent=2))
            parts.append(f'''  <details>
    <summary>Output</summary>
    <div class="detail-body">
      <pre>{output_json}</pre>
    </div>
  </details>
''')

        # Proof
        sig_short = _truncate(receipt.proof.signature, 32)
        merkle_short = _truncate(receipt.proof.merkle_root, 32)
        prev = _truncate(receipt.proof.previous_receipt, 32) if receipt.proof.previous_receipt else "\u2014"

        parts.append(f'''  <details>
    <summary>Proof</summary>
    <div class="detail-body">
      <div class="proof-grid">
        <span class="proof-label">signature</span>
        <span class="proof-value">{escape_html(sig_short)}</span>
        <span class="proof-label">merkle root</span>
        <span class="proof-value">{escape_html(merkle_short)}</span>
        <span class="proof-label">previous</span>
        <span class="proof-value">{escape_html(prev)}</span>
        <span class="proof-label">content hash</span>
        <span class="proof-value">{escape_html(content_hash)}</span>
      </div>
    </div>
  </details>
''')

        parts.append('</div>\n\n')

    # Footer
    parts.append('''<div class="footer">
  Generated by <strong>Manifest</strong> · Cryptographic receipts for AI agent tool calls<br>
  <a href="https://github.com/PortAuthorityHQ/manifest">github.com/PortAuthorityHQ/manifest</a>
</div>
</body>
</html>
''')

    return "".join(parts)
