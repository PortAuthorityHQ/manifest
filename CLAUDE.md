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
cargo test                     # Run all 125+ unit tests
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
| Watch command | `manifest-cli/src/commands/watch.rs` |
| Alert config | `manifest-proxy/src/receipt_builder.rs` (AlertConfig, emit_violation_alert) |
| SIEM sink config | `manifest-proxy/src/receipt_builder.rs` (SinkConfig, export_to_sink) |
| Homebrew formula | `Formula/manifest.rb` |
| npm wrapper | `npm/package.json`, `npm/install.js` |
| Python SDK | `sdk/python/manifest_sdk/` |
| Python SDK tests | `sdk/python/tests/` |
| Docs (policy, http, siem, identity, arch) | `docs/` |

## Python SDK

**PyO3-based** Python SDK — Rust bindings via `manifest-py` crate. No pure-Python reimplementation; all crypto, storage, and policy logic runs in Rust.

```
manifest-py/                    — PyO3 binding crate (cdylib)
├── Cargo.toml                  — Depends on manifest-core + pyo3 + pythonize
└── src/lib.rs                  — Python bindings: PySigner, PyMerkleTree, PyStorage, PyPolicyConfig, build_receipt

sdk/python/
├── pyproject.toml              — Maturin build backend, CLI entry point (manifest-py)
├── manifest_sdk/
│   ├── __init__.py             — Imports from manifest_py native module + Manifest class + Receipt wrapper
│   ├── cli.py                  — CLI (manifest-py): log, inspect, verify, export, watch, prune, init
│   └── html_template.py        — HTML export template (dark theme, matches Rust export.rs)
└── tests/                      — pytest
```

Key: all signing, hashing, Merkle tree, policy evaluation, and storage happen in Rust. The Python layer is just `Manifest` (orchestrator), `Receipt` (dict wrapper), CLI (argparse), and HTML template. Single source of truth — no dual maintenance.

Build: `cd manifest-py && maturin develop` or `pip install -e sdk/python` (requires Rust toolchain).

```bash
cd sdk/python && pip install -e . && pytest tests/ -v
```

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
- Policy rules: `tool-allowlist`, `spending-limit`, `pii-flag`, `pii-regex`, `rate-limit`. All support per-agent scoping via optional `agents` field on `PolicyEntry`.
- Policy `pii-flag` does substring matching (fast, false positives). Policy `pii-regex` does regex matching (precise, slower). Both can coexist.
- HTTP proxy uses per-session state keyed by `Mcp-Session-Id` header. Stdio proxy uses a single shared session. The receipt worker handles both via optional `SessionInfo` on `CapturedToolCall`.
- Regex patterns in `PolicyConfig` are compiled once via `OnceLock` and cached. Rate-limit counters use `Mutex<HashMap<String, u64>>` keyed by `"agent:tool"`. Don't construct `PolicyConfig` with struct literal — use `PolicyConfig::new(vec![...])` or `PolicyConfig::new_scoped(vec![...])` to ensure internal state fields are initialized.
- `PolicyEntry` wraps `PolicyRule` with an optional `agents: Vec<String>` field. `PolicyConfig.policies` is `Vec<PolicyEntry>`, not `Vec<PolicyRule>`. Use `PolicyConfig::new()` for global rules (wraps each rule in `PolicyEntry { agents: None, rule }`).
- `manifest prune` deletes receipts but NOT Merkle leaves — the Merkle tree is append-only by design.
- HTTP proxy bearer token auth (`--token`) is middleware-based. When set, all requests need `Authorization: Bearer <token>` or get 401.
- HTTP sessions have a 30-minute idle TTL (configurable via `MANIFEST_SESSION_TTL_SECS` env var). A background reaper task evicts expired sessions every 60 seconds. DELETE requests also clean up sessions immediately.
- Rate limiting uses a token bucket in `http_relay.rs` (not tower). The `RateLimiter` struct is behind `Arc<Mutex>` and shared across all requests.
- `/health` endpoint is NOT behind auth middleware — it's always accessible for load balancer probes.
- `--webhook` flag on proxy/proxy-http sends violation alerts as JSON POST to the configured URL. Violations are always logged to stderr regardless.
- `manifest watch` polls the database every 500ms. It only shows receipts created after the command starts (not historical). Uses color-coded status output (ANSI escape codes).
- `manifest export --format html` generates a self-contained HTML file with inline CSS (dark theme, GitHub-style). No JS, no external resources. All user content is HTML-escaped via `escape_html()` in export.rs.
- `StorageBackend` trait in `manifest-core/src/storage.rs` — all storage methods are on the trait, not inherent. Any file calling `Storage` methods must `use manifest_core::StorageBackend` or the methods won't resolve.
- `SpendingLimit` has an optional `field_path` for targeting specific JSON fields (dot notation `$.amount` or JSON pointer `/order/total`). When `None`, falls back to scanning all numeric values.
- `manifest verify --tree-only` validates Merkle tree structural integrity without needing a receipt hash or public key. Useful after pruning.
- GitHub Actions: `ci.yml` runs on push/PR to main (build + test + both e2e). `release.yml` triggers on `v*` tags and: (1) builds binaries for 4 targets, (2) generates `checksums.txt` and attaches it to the release, (3) auto-updates the Homebrew tap formula with real SHA256s via `HOMEBREW_TAP_TOKEN` secret, (4) verifies the npm postinstall binary download on Linux and macOS.
- HTTP proxy reqwest client has explicit `connect_timeout(5s)` and `timeout(30s)`. Body reads also have a 30s timeout returning 504 GATEWAY_TIMEOUT.
- HTTP proxy caps at 10,000 concurrent sessions (`MAX_SESSIONS`). New sessions beyond the cap get 503. Session cleanup happens on DELETE regardless of upstream success.
- `escape_html` in export.rs escapes `&` first to prevent double-escaping. Order matters — don't reorder the replace chain.
- `Proof.countersignatures` is `Option<Vec<Countersignature>>` — always `None` in the open-source CLI. Reserved for future Cloud Vault co-signing. The field is excluded from `canonical_bytes()` and `content_hash()`, so adding countersignatures never invalidates existing signatures.
- Homebrew formula is in `Formula/manifest.rb`. SHA256 checksums are placeholders — update them at each release.
- npm wrapper is in `npm/`. The `install.js` script downloads the right binary on `postinstall`. Requires a published GitHub release to work.
- `SinkConfig` in `receipt_builder.rs` follows the same pattern as `AlertConfig`. Both are `Clone` with an internal `reqwest::Client`. `SinkConfig::none()` creates a no-op config.
- `--sink`, `--sink-token`, `--sink-format` flags are on `proxy`, `proxy-http`, and `export` commands. The sink format is either `json` (raw receipt) or `splunk-hec` (wrapped in `{"event": ..., "sourcetype": "manifest:receipt"}`).
- Sink export is best-effort — errors are logged but never fail the receipt pipeline. Same pattern as webhook alerts.
- `export` command is async (uses `tokio::main`) to support the sink POST loop. The batch sink sends each receipt as a separate HTTP POST.
