# manifest-sdk

**Cryptographic receipts for AI agent tool calls — Python SDK.**

Pure Python implementation of the [manifest](https://github.com/PortAuthorityHQ/manifest) receipt format. Generates receipts that are byte-for-byte verifiable by the Rust CLI.

## Install

```bash
pip install manifest-sdk
```

## Quick Start

```python
from manifest_sdk import Manifest

m = Manifest(identity="my-agent", db="receipts.db")

receipt = m.record(
    tool="send_email",
    input={"to": "bob@example.com", "subject": "Hello"},
    output={"status": "sent"}
)

print(receipt.id)                    # urn:uuid:...
print(receipt.proof.signature)       # ed25519:...
print(receipt.content_hash())        # sha256:...
```

## Features

- **Ed25519 signing** — Key generation, signing, verification (32-byte seed files)
- **Merkle tree** — Append-only tree matching the Rust implementation
- **Policy evaluation** — Tool allowlists, spending limits, PII detection
- **SQLite storage** — Same schema as the Rust CLI (cross-readable)
- **Receipt chaining** — Each receipt links to the previous via content hash
- **JSON-LD receipts** — Same format as the MCP proxy

## Advanced Usage

```python
from manifest_sdk import (
    AgentIdentity, IdentitySource, Action, Delta,
    ReceiptBuilder, Signer, MerkleTree, Storage, PolicyConfig,
)

# Manual control over each component
signer = Signer.generate()
merkle = MerkleTree()
storage = Storage.open("receipts.db")

identity = AgentIdentity(
    name="procurement-bot",
    deployer="acme-corp",
    environment="production",
    source=IdentitySource.CONFIG,
)

receipt = (
    ReceiptBuilder()
    .agent(identity)
    .action(Action(tool="db_query", input={"sql": "SELECT 1"}, output={"rows": 1}))
    .delta(Delta(authorized=True))
    .build(signer, merkle)
)

storage.insert_receipt(receipt, session_id="session-1")

# Verify the signature
canonical = receipt.canonical_bytes()
assert signer.verify(canonical, receipt.proof.signature)
```

## License

[Apache 2.0](../../LICENSE)
