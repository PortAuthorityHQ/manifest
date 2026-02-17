# Contributing to manifest

Thanks for your interest in contributing to manifest. This document covers the basics.

## Prerequisites

- [Rust](https://rustup.rs/) 1.70+
- SQLite3 (optional, for inspecting the receipt database directly)

## Building

```bash
cargo build
```

## Testing

```bash
# Unit tests (70 tests across all crates)
cargo test

# End-to-end test (builds, runs proxy with mock server, verifies receipts)
./tests/e2e.sh

# Lint
cargo clippy -- -W clippy::all
```

## Project structure

| Crate | Purpose |
|-------|---------|
| `manifest-core` | Receipt types, Ed25519 signing, SHA-256, Merkle tree, SQLite storage |
| `manifest-proxy` | Async stdio relay, JSON-RPC parsing, MCP interception, receipt worker |
| `manifest-cli` | Binary with subcommands (`proxy`, `log`, `inspect`, `export`, `init`) |
| `mock-mcp-server` | Test fixture: mock MCP server for e2e testing |

## Making changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add tests for new functionality
4. Run `cargo test` and `cargo clippy` — both must pass
5. Open a pull request

## Pull request guidelines

- Keep PRs focused on a single change
- Include tests for new features or bug fixes
- Update the README if you change CLI behavior or add new commands
- Run `./tests/e2e.sh` to verify the full pipeline works

## Reporting issues

Open an issue at [github.com/port-authority/manifest/issues](https://github.com/port-authority/manifest/issues).

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
