# Agent Identity

Every receipt includes an identity field identifying the agent that made the tool call.

## Sources (Priority Order)

| Priority | Source | How | `verified` |
|----------|--------|-----|------------|
| 1 | Config file | Declared in YAML, passed via `--identity` | `false` |
| 2 | MCP handshake | Auto-extracted from `initialize` request (`clientInfo.name`) | `false` |
| 3 | Environment | Process name + hostname | `false` |

`manifest` uses the highest-priority source available. You always get an identity — it's never empty.

## Config File

```yaml
# identity.yaml
agent:
  name: "procurement-bot"
  deployer: "acme-corp"
  environment: "production"
```

```bash
manifest proxy --server "your-server" --identity identity.yaml
```

## MCP Handshake

If no config file is provided, `manifest` extracts identity from the MCP `initialize` handshake:

```json
{
  "method": "initialize",
  "params": {
    "clientInfo": { "name": "claude-desktop", "version": "2.0" }
  }
}
```

This is automatic — no configuration needed.

## Verification

In the open-source version, identity is self-declared. An agent can claim to be anything. The receipt is honest about this: `"verified": false`.

The receipt schema supports verified identity (SPIFFE/SVID, mTLS certificate chains) where the field flips to `"verified": true`. Same schema, no migration needed.
