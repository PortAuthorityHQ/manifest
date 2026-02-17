# CLAUDE.md

Project-specific instructions for Claude Code working on this repository.

## Project Overview

**manifest** — a Rust MCP proxy that generates cryptographic receipts for AI agent tool calls. Intercepts JSON-RPC traffic between agents and MCP servers, signs each tool call with Ed25519, and chains receipts in an append-only Merkle tree.

## Architecture

Cargo workspace with 3 crates + 1 test binary:

```
manifest-core/     — Receipt types, crypto (Ed25519, SHA-256, Merkle), SQLite storage. No async, no tokio.
manifest-proxy/    — Async stdio + HTTP relay, JSON-RPC parsing, MCP interception, receipt worker.
manifest-cli/      — Binary entry point + clap subcommands. Thin shell over core + proxy.
mock-mcp-server/   — Test MCP server with echo/add/db_query/fail/slow tools. Supports both stdio and --http mode.
```

**Dependency direction**: cli → proxy → core. Core has zero async dependencies.

## Key Design Decisions

- **Raw byte forwarding** — Relay forwards raw bytes, not re-serialized JSON. Preserves exact messages.
- **Response before receipt** — Agent sees the response BEFORE receipt generation begins. Signing is async.
- **Signing order** — Sign canonical bytes (excludes signature + merkle_root) → compute content_hash (includes signature, excludes merkle_root) → append to Merkle tree → set merkle_root. This avoids circular dependencies.
- **Merkle proofs are directional** — `Vec<(bool, [u8; 32])>` where `bool` = sibling is on the left. Required for correct verification with odd-numbered leaf sets.
- **Receipt errors never propagate** — If receipt generation fails, the error is logged but the relay continues. The proxy must be transparent.
- **spawn_blocking for SQLite** — Signing + SQLite writes happen on blocking threads via `tokio::task::spawn_blocking` to avoid stalling the tokio runtime.
- **Canonical JSON** — `serde_json` uses `BTreeMap` by default (sorted keys). Do NOT enable the `preserve_order` feature on serde_json.

## Common Commands

```bash
cargo build                    # Build all crates
cargo test                     # Run all 94+ unit tests
bash tests/e2e.sh              # Stdio e2e test (build + proxy + receipts + verify + policy)
bash tests/e2e_http.sh         # HTTP e2e test (build + HTTP proxy + receipts + verify + auth)
cargo test -p manifest-core    # Test just core
cargo test -p manifest-proxy   # Test just proxy
```

## File Locations

| What | Where |
|------|-------|
| Receipt struct + builder | `manifest-core/src/receipt.rs` |
| Ed25519 signing | `manifest-core/src/signing.rs` |
| Merkle tree | `manifest-core/src/merkle.rs` |
| SQLite storage | `manifest-core/src/storage.rs` |
| Policy evaluation | `manifest-core/src/policy.rs` |
| JSON-RPC parsing | `manifest-proxy/src/jsonrpc.rs` |
| Stdio relay | `manifest-proxy/src/relay.rs` |
| HTTP relay | `manifest-proxy/src/http_relay.rs` |
| Receipt worker | `manifest-proxy/src/receipt_builder.rs` |
| MCP session state | `manifest-proxy/src/session.rs` |
| CLI entry point | `manifest-cli/src/main.rs` |
| E2E test (stdio) | `tests/e2e.sh` |
| E2E test (HTTP) | `tests/e2e_http.sh` |
| Prune command | `manifest-cli/src/commands/prune.rs` |

## Conventions

- Signatures use `"ed25519:<base64>"` format.
- Content hashes use `"sha256:<hex>"` format.
- Receipt IDs use `"urn:uuid:<uuid-v7>"` format (time-ordered).
- Public key files use `.pub` extension appended to the key path (e.g., `signing.key.pub`).
- Default data directory: `~/.manifest/` (signing.key, receipts.db).
- All CLI query commands accept `--db` for custom database path.
- Tracing goes to stderr. stdout is reserved for MCP protocol traffic in proxy mode.

## Gotchas

- The `hostname` crate is used in `identity.rs` for environment fallback — don't remove it.
- `hex` is a dependency of both manifest-core and manifest-proxy (used in receipt_builder.rs for hash decoding).
- The relay spawns agent→child as a separate tokio task. The main task runs child→agent. This is intentional — `tokio::select!` exits on stdin EOF before the child responds.
- Graceful shutdown: when the relay exits, `receipt_tx` is dropped, closing the channel. The receipt worker drains remaining items. The proxy awaits this with a 10s timeout.
- Payload truncation happens in the receipt worker (blocking thread), not in the relay. The relay always forwards full payloads.
- Policy `pii-flag` does substring matching (fast, false positives). Policy `pii-regex` does regex matching (precise, slower). Both can coexist.
- HTTP proxy uses per-session state keyed by `Mcp-Session-Id` header. Stdio proxy uses a single shared session. The receipt worker handles both via optional `SessionInfo` on `CapturedToolCall`.
- Regex patterns in `PolicyConfig` are compiled once via `OnceLock` and cached. Don't construct `PolicyConfig` with struct literal — use `PolicyConfig::new(vec![...])` to ensure the cache field is initialized.
- `manifest prune` deletes receipts but NOT Merkle leaves — the Merkle tree is append-only by design.
- HTTP proxy bearer token auth (`--token`) is middleware-based. When set, all requests need `Authorization: Bearer <token>` or get 401.
- HTTP sessions have a 30-minute idle TTL (configurable via `MANIFEST_SESSION_TTL_SECS` env var). A background reaper task evicts expired sessions every 60 seconds. DELETE requests also clean up sessions immediately.
- Rate limiting uses a token bucket in `http_relay.rs` (not tower). The `RateLimiter` struct is behind `Arc<Mutex>` and shared across all requests.
- `/health` endpoint is NOT behind auth middleware — it's always accessible for load balancer probes.
