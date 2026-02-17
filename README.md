# manifest

**Cryptographic receipts for AI agent tool calls.**

Stop guessing what your agents are doing. Start proving it.

---

`manifest` is a high-performance Rust proxy that sits between your AI agent and the tools it calls. Every tool interaction is intercepted, signed, and sealed into a tamper-proof receipt — linking what the agent *did* to what it was *authorized* to do.

When a transaction is disputed, you don't show a dashboard. You show a signed manifest.

## Why This Exists

AI agents are moving money, accessing PII, and making consequential decisions. But when something goes wrong, enterprises have no forensic evidence — just mutable logs that prove nothing.

`manifest` closes that gap:

- **Evidence, not logs.** Every tool call is hashed (SHA-256), signed (Ed25519), and chained into a Merkle tree. Receipts are immutable and independently verifiable.
- **Bidirectional proof.** Each receipt captures what was *authorized* (policy snapshot) alongside what *actually happened* (input/output). The delta between them is the accountability record.
- **Sub-millisecond overhead.** Written in Rust on Tokio. Your agent won't feel it.
- **MCP-native.** Built for the MCP `tools/call` protocol. REST/gRPC support planned.

## How It Works

`manifest` wraps your MCP server process. It spawns the server as a child process, sits on the stdio pipes, and intercepts every JSON-RPC message passing between your agent and the tool server. The agent and server are unaware it exists.

```
┌─────────┐  stdio   ┌──────────────┐  stdio  ┌──────────┐
│  Agent  │────────▶ │   manifest   │────────▶│   MCP    │
│ (Claude,│◀──────── │              │◀────────│  Server  │
│  GPT,   │  stdin/  │  intercept   │  stdin/ │          │
│  custom)│  stdout  │  sign & seal │  stdout │          │
└─────────┘          └──────────────┘         └──────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   Receipt    │
                     │   Store      │
                     └──────────────┘
```

1. **Intercept** — Captures `tools/call` requests and responses as they pass through the stdio pipe. Handles the full MCP session lifecycle (initialization, notifications, errors) transparently.
2. **Snapshot** — Records the active authorization policy at the moment of the call (optional — receipts are still valuable without policies configured).
3. **Sign & Seal** — Buffers the complete response, then bundles identity, policy, action, and result into a signed JSON-LD receipt with Merkle tree linkage.
4. **Forward** — Passes traffic through. Signing happens asynchronously after the response is forwarded to minimize added latency.

## Installation

Requires [Rust](https://rustup.rs/) (1.70+).

```bash
# Clone and build
git clone https://github.com/port-authority/manifest.git
cd manifest
cargo build --release

# The binary is at target/release/manifest
# Optionally, install it to your PATH:
cargo install --path manifest-cli
```

## Quick Start

Wrap any existing MCP server. `manifest` spawns it as a child process and intercepts all tool calls over stdio:

```bash
# Build from source
cargo build --release

# Generate a signing keypair
manifest init

# Wrap a local Postgres MCP server
manifest proxy --server "npx @modelcontextprotocol/server-postgres postgresql://localhost/mydb"

# Wrap any MCP server
manifest proxy --server "your-mcp-server-command"

# With real-time violation alerts via webhook
manifest proxy --server "your-mcp-server-command" --policy manifest.policy.yml \
    --webhook https://hooks.slack.com/services/...
```

Point your agent's MCP client config at `manifest` instead of the server directly:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "manifest",
      "args": ["proxy", "--server", "npx @modelcontextprotocol/server-postgres postgresql://localhost/mydb"]
    }
  }
}
```

Everything else works the same — your agent doesn't know it's being recorded.

Receipts are generated on every `tools/call`. Query them via the CLI:

```bash
# View the last 10 receipts
manifest log --tail 10

# Show full receipt detail including any errors or policy violations
manifest inspect <receipt-hash>

# Export an audit-ready bundle for a session
manifest export --session <session-id> --format json

# Generate a shareable HTML report (self-contained, no dependencies)
manifest export --format html --output report.html

# Verify a receipt's signature, hash, and Merkle proof
manifest verify <receipt-hash> --public-key ~/.manifest/signing.key.pub

# Delete receipts older than 90 days
manifest prune --older-than 90d

# Dry run — see what would be deleted without deleting
manifest prune --older-than 30d --dry-run

# Live-tail receipts as they are generated
manifest watch

# Filter by tool name or session
manifest watch --tool db_query
manifest watch --session <session-id>
```

## The Receipt

Each tool interaction produces a JSON-LD receipt containing four layers:

| Layer | What It Captures | How |
|-------|-----------------|-----|
| **Identity** | Who is the agent? Who deployed it? | Auto-detected or declared (see [Agent Identity](#agent-identity)) |
| **Policy** | What was it authorized to do at this moment? | YAML config or OPA/Rego (optional) |
| **Action** | What did it actually send and receive? | Input params + tool output |
| **Proof** | Cryptographic seal binding it all together | Ed25519 signature + Merkle root |

Example receipt (simplified):

```json
{
  "@context": "https://portauthority.dev/receipt/v1",
  "id": "urn:uuid:01956a3b-...",
  "timestamp": "2026-02-16T14:23:01.847Z",
  "agent": {
    "name": "procurement-bot",
    "deployer": "acme-corp",
    "source": "config",
    "verified": false
  },
  "policy": {
    "maxTransactionValue": 50000,
    "allowedTools": ["db_query", "send_email"],
    "snapshot": "sha256:a1b2c3..."
  },
  "action": {
    "tool": "db_query",
    "input": { "query": "SELECT * FROM orders WHERE value > 10000" },
    "output": { "rows": 42 }
  },
  "delta": {
    "authorized": true,
    "violations": []
  },
  "proof": {
    "signature": "ed25519:...",
    "merkleRoot": "sha256:d4e5f6...",
    "previousReceipt": "sha256:c3d4e5..."
  }
}
```

Errors get receipts too. If a tool call fails, times out, or the server crashes mid-response, the receipt captures exactly what happened:

```json
{
  "action": {
    "tool": "db_query",
    "input": { "query": "DROP TABLE users" },
    "output": null,
    "error": { "code": -32603, "message": "permission denied" }
  },
  "delta": {
    "authorized": false,
    "violations": ["tool_not_in_allowlist"]
  }
}
```

If you instructed "authorize up to $50K" and the agent submitted a tool call for $100K — the delta is right there, cryptographically sealed, with the policy that was active at that exact moment.

## Agent Identity

Every receipt includes an identity field. How it gets populated depends on what's available:

| Source | How It Works | `verified` |
|--------|-------------|------------|
| **MCP client info** | Auto-extracted from the `initialize` handshake (`clientInfo.name`, `clientInfo.version`) | `false` |
| **Config file** | Declared in `manifest.identity.yml` (agent name, deployer, environment) | `false` |
| **Environment** | Falls back to process name, PID, and hostname | `false` |
| **SPIFFE/SVID** *(enterprise)* | Cryptographically verified via mTLS certificate chain | `true` |

In the open-source version, identity is **self-declared** — useful for debugging, tracing, and distinguishing between agents, but not cryptographically verified. The receipt is honest about this: `"verified": false`.

The receipt schema is the same regardless of source. When you upgrade to verified identity, the field flips to `"verified": true` with a certificate chain. No schema migration. No receipt format change.

Configure identity explicitly:

```yaml
# manifest.identity.yml
agent:
  name: "procurement-bot"
  deployer: "acme-corp"
  environment: "production"
```

```bash
manifest proxy --server "your-server" --identity manifest.identity.yml
```

Without a config file, `manifest` auto-populates identity from the MCP `initialize` handshake and the runtime environment. Every receipt always has an identity field — it's never empty.

## Performance

| Metric | Value |
|--------|-------|
| Signing overhead | ~50μs per receipt (Ed25519) |
| Memory footprint | ~15MB |
| Runtime | Rust + Tokio async I/O |
| Signing | Ed25519 (ed25519-dalek) |
| Hashing | SHA-256, Merkle tree chaining |
| Impact on tool calls | Signing is async — responses are forwarded before the receipt is sealed |

Note: total receipt generation time (serialization + hashing + signing + Merkle append) depends on response payload size. For typical tool call responses (<100KB), expect <1ms. Larger payloads take proportionally longer but do not block the agent since signing is asynchronous.

## Policy Configuration (Optional)

Policies are optional. Without them, `manifest` still generates signed receipts for every tool call — you get cryptographic proof of what happened. With policies, you also get proof of whether it was authorized.

Define policies in a simple YAML file:

```yaml
# manifest.policy.yml
policies:
  - name: spending-limit
    max_transaction_value: 50000

  - name: tool-allowlist
    allowed_tools:
      - db_query
      - send_email
      - read_file

  - name: pii-flag
    flag_if_contains:
      - SSN
      - credit_card
      - date_of_birth
```

```bash
manifest proxy --server "your-server" --policy manifest.policy.yml
```

The `pii-regex` rule provides built-in patterns for common PII types and supports custom regex:

```yaml
# manifest.policy.yml
policies:
  - name: pii-regex
    builtin:
      - ssn           # US Social Security Numbers (XXX-XX-XXXX)
      - credit_card   # Major credit card numbers
      - email         # Email addresses
      - phone         # US phone numbers
    custom:
      passport: '\b[A-Z]\d{8}\b'
```

The simpler `pii-flag` rule uses case-insensitive substring matching (faster, but prone to false positives like "assign" matching "ssn"). Use `pii-regex` when precision matters.

Full OPA/Rego integration is on the roadmap for enterprise use cases.

## Use Cases

**Compliance** — EU AI Act (Article 12) requires automatic event recording for high-risk AI systems by August 2026. Colorado SB24-205 requires demonstrable "reasonable care" by June 2026. `manifest` generates the evidence trail automatically.

**Vendor disputes** — When an LLM returns output that exceeds your instructions, you have cryptographic proof of the input/output mismatch and the active policy. You may not win every dispute, but you won't lose one for lack of evidence.

**Insurance** — Insurers are adding AI exclusions to E&O and D&O policies. Receipts become your proof that controls are operational, not theoretical.

**Debugging** — When an agent loops, burns credits, or hallucinates tool parameters, the receipt chain gives you the exact trace with cryptographic ordering.

## HTTP/SSE Transport

For remote MCP servers using the Streamable HTTP transport, use `proxy-http` instead of `proxy`:

```bash
# Proxy a remote MCP server
manifest proxy-http --upstream http://localhost:9090/mcp --port 8080

# With policy and identity
manifest proxy-http --upstream http://mcp.example.com/mcp --port 8080 \
    --policy manifest.policy.yml --identity manifest.identity.yml

# With bearer token authentication (rejects unauthenticated requests)
manifest proxy-http --upstream http://localhost:9090/mcp --port 8080 --token my-secret-token
```

Then point your agent at `http://localhost:8080/mcp` instead of the upstream server. The proxy handles POST, GET (SSE), and DELETE methods transparently. When `--token` is set, all requests must include `Authorization: Bearer <token>` or receive a 401 response. Each concurrent client gets isolated session state via the `Mcp-Session-Id` header.

Additional options:

- `--webhook <URL>` — POST policy violation alerts to a webhook (Slack, PagerDuty, etc.)
- `--rate-limit 100` — Limit to 100 requests per second (excess gets 429)
- A `/health` endpoint returns `{"status":"ok"}` for load balancer probes

### Deploying with TLS

The HTTP proxy serves plaintext on `127.0.0.1`. For network deployments, use a reverse proxy to terminate TLS:

**Caddy** (automatic HTTPS):
```
mcp.example.com {
    reverse_proxy localhost:8080
}
```

**nginx**:
```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;

    ssl_certificate     /etc/ssl/certs/mcp.example.com.pem;
    ssl_certificate_key /etc/ssl/private/mcp.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;  # Required for SSE streaming
    }
}
```

## Known Limitations

**Spending limits check all numeric values.** The spending limit policy scans every numeric value in the JSON input recursively. A tool call like `{"page": 50000, "limit": 100}` would trigger a violation for the pagination parameter. There is no way to specify which field represents monetary value — all numbers are checked.

**PII string matching has false positives.** The `pii-flag` rule uses case-insensitive substring matching, so "assign" matches "ssn". Use the `pii-regex` rule for precise pattern matching when this is a concern.

**Single-writer SQLite.** The `Arc<Mutex<Storage>>` pattern works for a single proxy instance. Running two proxy instances pointing at the same database file will cause lock contention. Use separate database files for concurrent proxies.

**Receipt payload truncation.** Tool outputs larger than 256 KB (configurable via `MANIFEST_MAX_PAYLOAD_BYTES`) are replaced with a SHA-256 hash reference in the receipt. The original payload is not stored — only its hash. This prevents SQLite bloat but means large outputs cannot be fully reconstructed from receipts alone.

**Identity is self-declared.** In the open-source version, agent identity comes from the MCP handshake, a config file, or the environment. None of these sources are cryptographically verified (`"verified": false`). An agent can claim to be anything.

**Pruning does not remove Merkle leaves.** `manifest prune` deletes receipt records from SQLite but leaves the Merkle tree intact (it is append-only by design). After pruning, `manifest verify` will fail for deleted receipts since the receipt JSON is gone, but the Merkle tree remains consistent for non-pruned receipts. Pruning is for storage management, not for Merkle tree maintenance.

**No TLS built in.** The HTTP proxy binds to `127.0.0.1` and serves plaintext HTTP. For network deployments, place a reverse proxy (nginx, caddy) in front to terminate TLS. Bearer tokens travel in plaintext without TLS.

## What This Does NOT Capture

`manifest` captures the decision chain (what tools were called, in what order, with what inputs and outputs) and the authorization context (what policies were active). It does **not** capture the LLM's internal reasoning or chain-of-thought — that lives inside the provider's inference pipeline.

This is still more than any enterprise currently has.

## Roadmap

- [x] stdio MCP proxy (spawn + intercept)
- [x] Receipt generation (JSON-LD + Ed25519 + Merkle tree)
- [x] CLI tooling (`log`, `inspect`, `export`)
- [x] Agent identity (auto-detect from MCP handshake + config file + environment)
- [x] YAML policy engine (tool allowlists, spending limit schema)
- [x] Policy evaluation (spending limit enforcement, PII detection, regex patterns)
- [x] Receipt verification (`manifest verify` — signature, hash, Merkle proof, chain)
- [x] HTTP/SSE MCP transport (`manifest proxy-http` — Streamable HTTP reverse proxy)
- [x] Receipt size limits (auto-truncation of oversized payloads with hash reference)
- [x] HTTP proxy authentication (bearer token + per-session state isolation)
- [x] Database retention (`manifest prune --older-than 90d`)
- [x] Real-time violation alerts (`--webhook` + stderr logging)
- [x] Live receipt tailing (`manifest watch`)
- [x] HTML export (`manifest export --format html` — shareable, self-contained report)

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

## License

[Apache 2.0](LICENSE)

---

<p align="center">
  <strong>Port Authority</strong><br/>
  Cryptographic evidence for the agentic economy.
</p>
