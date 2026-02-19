# Architecture

## How It Works

`manifest` wraps your MCP server as a child process and intercepts all JSON-RPC messages over stdio. The agent and server are unaware it exists.

```
┌─────────┐  stdio   ┌──────────────┐  stdio  ┌──────────┐
│  Agent  │────────► │   manifest   │────────►│   MCP    │
│         │◀──────── │              │◀────────│  Server  │
└─────────┘          └──────────────┘         └──────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   SQLite DB  │
                     └──────────────┘
```

1. **Intercept** — Captures `tools/call` requests and responses
2. **Snapshot** — Records the active policy at the moment of the call
3. **Sign & Seal** — Signs the receipt (Ed25519) and appends to the Merkle tree
4. **Forward** — Passes traffic through. Signing is async — responses are forwarded before the receipt is sealed

## Receipt Format

JSON-LD with four layers:

| Layer | What | How |
|-------|------|-----|
| **Identity** | Who is the agent? | MCP handshake, config file, or environment |
| **Policy** | What was it authorized to do? | YAML config snapshot |
| **Action** | What did it actually do? | Tool name, input params, output |
| **Proof** | Cryptographic seal | Ed25519 signature + Merkle root + chain hash |

## Cryptography

- **Signing**: Ed25519 (ed25519-dalek)
- **Hashing**: SHA-256
- **Chaining**: Merkle tree — each receipt includes the current tree root and previous receipt hash
- **Key storage**: `~/.manifest/signing.key` (private) and `~/.manifest/signing.key.pub` (public)

## Performance

| Metric | Value |
|--------|-------|
| Signing overhead | ~50us per receipt |
| Memory footprint | ~15MB |
| Impact on tool calls | None — signing is async |

## Storage

Receipts are stored in SQLite at `~/.manifest/receipts.db`. The storage layer uses a `StorageBackend` trait for future backend support.

Payload truncation: tool outputs larger than 256 KB (configurable via `MANIFEST_MAX_PAYLOAD_BYTES`) are replaced with a SHA-256 hash reference.

## Known Limitations

- **Single-writer SQLite.** Don't point two proxy instances at the same database file.
- **Identity is self-declared.** Agents can claim to be anything (`"verified": false`).
- **No built-in TLS.** The HTTP proxy serves plaintext. Use a reverse proxy for TLS.
- **Pruning keeps Merkle leaves.** `manifest prune` deletes receipts but the Merkle tree is append-only. Use `manifest verify --tree-only` after pruning.
- **Spending limits check all numbers by default.** Use `field_path` to target the right field.
- **PII string matching has false positives.** Use `pii-regex` instead of `pii-flag` for precision.
